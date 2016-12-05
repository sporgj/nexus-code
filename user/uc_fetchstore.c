#include <stdlib.h>

#include "third/seqptrmap.h"
#include "third/slog.h"

#include "uc_dcache.h"
#include "uc_fetchstore.h"
#include "uc_filebox.h"
#include "uc_sgx.h"
#include "uc_types.h"
#include "uc_uspace.h"
#include "uc_utils.h"

static struct seqptrmap * xfer_context_array = NULL;

static void
free_xfer_context(xfer_context_t * xfer_ctx)
{
    if (xfer_ctx->path) {
        free(xfer_ctx->path);
    }

    if (xfer_ctx->buffer) {
        free(xfer_ctx->buffer);
    }

    if (xfer_ctx->fbox) {
        free(xfer_ctx->fbox);
    }

    free(xfer_ctx);
}

int
fetchstore_start(int op,
                 char * fpath,
                 uint32_t max_xfer_size,
                 uint32_t file_offset,
                 uint32_t file_size,
                 int * xfer_id,
                 uint32_t * fbox_len,
                 uint32_t * total_len)
{
    int ret = -1;
    uc_fbox_t * fbox;
    ucafs_entry_type atype;
    uc_dirnode_t * dirnode = NULL;
    sds fname_sds = NULL;
    const shadow_t * shdw_name;
    xfer_context_t * xfer_ctx = NULL;

    if ((op & UC_ENCRYPT) && (op & UC_DECRYPT)) {
        slog(0, SLOG_ERROR, "can't encrypt and decrypt at the same time");
        return ret;
    }

    if ((fname_sds = do_get_fname(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "can't retrieve fname '%s'");
        return ret;
    }

    if ((dirnode = dcache_lookup(fpath, false)) == NULL) {
        slog(0, SLOG_ERROR, "dirnode '%s' not found");
        sdsfree(fname_sds);
        return ret;
    }

    /* If not found, we don't have access to this file. */
    shdw_name = dirnode_raw2enc(dirnode, fname_sds, UC_ANY, &atype);
    if (shdw_name == NULL) {
        slog(0, SLOG_ERROR, "finding '%s' in dirnode FAILED", fpath);
        goto out;
    }

    xfer_ctx = (xfer_context_t *)calloc(1, sizeof(xfer_context_t));
    if (xfer_ctx == NULL) {
        slog(0, SLOG_FATAL, "fileops - memory allocation failed");
        goto out;
    }

    // XXX check the size of max_xfer_size
    xfer_ctx->buffer = (char *)malloc(max_xfer_size);
    if (xfer_ctx->buffer == NULL) {
        slog(0, SLOG_FATAL, "fileops - xfer_ctx buffer allocation failed");
        goto out;
    }

    xfer_ctx->op = op;
    xfer_ctx->completed = 0;
    xfer_ctx->buflen = max_xfer_size;
    xfer_ctx->position = file_offset;
    xfer_ctx->total_len = file_size;
    xfer_ctx->path = strdup(fpath);

    if (op == UCAFS_STORE) {
        xfer_ctx->fbox = fbox = calloc(1, sizeof(uc_fbox_t));
        if (fbox == NULL) {
            slog(0, SLOG_FATAL, "alloating fbox (%s) failed", fpath);
            goto out;
        }

        /* setup the fbox */
        fbox->magic = UCAFS_FBOX_MAGIC;
        // XXX change here for multichunking
        fbox->chunk_count = 1;
        fbox->chunk_size = file_size;
        fbox->file_size = file_size;
        fbox->fbox_len = sizeof(uc_fbox_t);
    }

    /* TODO move this to an init function */
    if (xfer_context_array == NULL) {
        xfer_context_array = seqptrmap_init();
    }

    if (xfer_ctx->op == UCAFS_STORE) {
#ifdef UCAFS_SGX
        ecall_xfer_start(global_eid, &ret, xfer_ctx);
        if (ret) {
            slog(0, SLOG_FATAL, "enclave failed");
            goto out;
        }
#endif
    }

    xfer_ctx->xfer_id = seqptrmap_add(xfer_context_array, xfer_ctx);
    if (xfer_ctx->xfer_id == -1) {
        // TODO delete context from enclave space
        slog(0, SLOG_ERROR, "fileops - Adding to list failed");
        goto out;
    }

    *fbox_len = fbox->fbox_len;
    // XXX don't forget to add the size of the MAC in the future
    *total_len = fbox->fbox_len + fbox->file_size;
    *xfer_id = xfer_ctx->xfer_id;
    ret = 0;
out:
    if (ret && xfer_ctx) {
        *xfer_id = -1;
        free_xfer_context(xfer_ctx);
    }

    sdsfree(fname_sds);
    return ret;
}

uint8_t ** fetchstore_get_buffer(int id, size_t valid_buflen, int * op)
{
    xfer_context_t * xfer_ctx = seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        slog(0, SLOG_ERROR, "fileops - id=%d could not be found", id);
        return NULL;
    }

    if (valid_buflen > xfer_ctx->buflen) {
        slog(0, SLOG_ERROR, "fileops - id (%d) valid buflen too big (%d > %d)",
             id, valid_buflen, xfer_ctx->buflen);
        return NULL;
    }

    xfer_ctx->valid_buflen = valid_buflen;
    *op = xfer_ctx->op;
    return (uint8_t **)&xfer_ctx->buffer;
}

int fetchstore_process_data(uint8_t ** buffer)
{
    int ret = 0, len;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)((uintptr_t)buffer
                             - offsetof(xfer_context_t, buffer));

#ifdef UCAFS_SGX
    ecall_xfer_crypto(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_FATAL, "enclave crypto failed");
        goto out;
    }
#endif

    xfer_ctx->completed += xfer_ctx->valid_buflen;
    ret = 0;
out:
    if (ret) {
        // XXX is this necessary? Just because one fails?
        fetchstore_finish(xfer_ctx->xfer_id);
    }

    return ret;
}

int fetchstore_process_fbox(uint8_t ** buffer)
{
    int ret = -1, bytes_left, len;
    uc_fbox_t * fbox;
    uint8_t * fbox_buffer;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)((uintptr_t)buffer
                             - offsetof(xfer_context_t, buffer));
    fbox = xfer_ctx->fbox;

    bytes_left = fbox->fbox_len - xfer_ctx->fbox_xfer;
    if (bytes_left <= 0) {
        slog(0, SLOG_FATAL, "trying to read beyond fbox");
        goto out;
    }

    len = MIN(bytes_left, xfer_ctx->valid_buflen);
    fbox_buffer = ((uint8_t *) fbox) + xfer_ctx->fbox_xfer;

    xfer_ctx->fbox_xfer += len;

    if (xfer_ctx->op == UCAFS_STORE) {
        memcpy(xfer_ctx->buffer, fbox_buffer, len);
    } else {
        memcpy(fbox_buffer, xfer_ctx->buffer, len);

        // if we have exceeded the maximum, time to instantiate
        if (xfer_ctx->fbox_xfer >= fbox->fbox_len) {
#ifdef UCAFS_SGX
            ecall_xfer_start(global_eid, &ret, xfer_ctx);
            if (ret) {
                slog(0, SLOG_FATAL, "enclave failed");
                goto out;
            }
#endif
        }
    }

    ret = 0;
out:
    if (ret) {
        // XXX is this necessary? Just because one fails?
        fetchstore_finish(xfer_ctx->xfer_id);
    }
    return ret;
}

int
fetchstore_finish(int id)
{
    xfer_context_t * xfer_ctx;
    crypto_mac_t crypto_mac;
    int ret = -2;

    xfer_ctx = seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        return ret;
    }

#ifdef UCAFS_SGX
    /* now we can proceed with the crypto stuff */
    ecall_xfer_finish(global_eid, &ret, xfer_ctx, &crypto_mac);
    if (ret) {
        slog(0, SLOG_ERROR, "fileops - Crypto operation failed");
        goto out;
    }
#endif

    ret = 0;
out:
    seqptrmap_delete(xfer_context_array, id);
    free_xfer_context(xfer_ctx);

    return ret;
}
