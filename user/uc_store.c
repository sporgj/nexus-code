#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "enclave_u.h"

#include "third/sds.h"
#include "third/seqptrmap.h"
#include "third/slog.h"

#include "uc_dcache.h"
#include "uc_dirnode.h"
#include "uc_fetchstore.h"
#include "uc_sgx.h"
#include "uc_utils.h"

static struct seqptrmap * xfer_context_array = NULL;

static int
free_xfer_context(xfer_context_t * xfer_ctx)
{
    if (xfer_ctx->xfer_id != -1) {
        seqptrmap_delete(xfer_context_array, xfer_ctx->xfer_id);
    }

    if (xfer_ctx->buffer) {
        free(xfer_ctx->buffer);
    }

    if (xfer_ctx->fbox) {
        free(xfer_ctx->fbox);
    }

    if (xfer_ctx->path) {
        free(xfer_ctx->path);
    }

    free(xfer_ctx);
}

int
store_start(char * fpath,
            uint16_t max_xfer_size,
            uint32_t offset,
            uint32_t file_size,
            int old_fbox_len,
            int * xfer_id,
            int * new_fbox_len)
{
    int ret = -1;
    sds fname_sds = NULL;
    uc_fbox_t * fbox;
    xfer_context_t * xfer_ctx = NULL;
    const shadow_t * shdw_name;
    uc_dirnode_t * dirnode;
    ucafs_entry_type atype;
    int chunk_count;

    /* lets find the dirnode object first */
    if ((dirnode = dcache_lookup(fpath, false)) == NULL) {
        slog(0, SLOG_ERROR, "finding dirnode failed: '%s'", fpath);
        return ret;
    }

    if ((fname_sds = do_get_fname(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "retrieving file name failed '%s'", fpath);
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

    xfer_ctx->xfer_id = -1;
    xfer_ctx->op = UCAFS_STORE;
    xfer_ctx->completed = 0;
    xfer_ctx->buflen = max_xfer_size;
    xfer_ctx->position = offset;
    xfer_ctx->total_len = file_size;
    xfer_ctx->path = strdup(fpath);

    // TODO integrate old_fbox_len
    xfer_ctx->fbox = fbox = calloc(1, FBOX_SIZE(file_size));
    if (fbox == NULL) {
        slog(0, SLOG_FATAL, "alloating fbox (%s) failed", fpath);
        goto out;
    }

    fbox->chunk_count = FBOX_CHUNK_COUNT(file_size);
    fbox->chunk_size = UCAFS_CHUNK_SIZE;
    fbox->fbox_len = FBOX_SIZE(file_size);
    fbox->file_size = file_size;

    /* TODO move this to an init function */
    if (xfer_context_array == NULL) {
        xfer_context_array = seqptrmap_init();
    }

    xfer_ctx->xfer_id = seqptrmap_add(xfer_context_array, xfer_ctx);
    if (xfer_ctx->xfer_id == -1) {
        // TODO delete context from enclave space
        slog(0, SLOG_ERROR, "fileops - Adding to list failed");
        goto out;
    }

#ifdef UCAFS_SGX
    ecall_store_init(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_ERROR, "Enclave error");
        goto out;
    }

    ecall_store_start(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_FATAL, "enclave error");
        goto out;
    }
#endif

    *new_fbox_len = 0; //fbox->fbox_len;
    *xfer_id = xfer_ctx->xfer_id;
    ret = 0;
out:
    if (fname_sds) {
        sdsfree(fname_sds);
    }

    if (ret) {
        *xfer_id = -1;
        free_xfer_context(xfer_ctx);
    }

    dcache_put(dirnode);
    return ret;
}

uint8_t **
store_get_buffer(int id, size_t valid_buflen)
{
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)seqptrmap_get(xfer_context_array, id);

    if (xfer_ctx == NULL) {
        slog(0, SLOG_ERROR, "xfer_ctx id=%d not found", id);
        return NULL;
    }

    if (valid_buflen > xfer_ctx->buflen) {
        slog(0, SLOG_ERROR, "valid_buflen exceeds buffer (%d > %d)",
             valid_buflen, xfer_ctx->buflen);
        // TODO delete the xfer context here
        return NULL;
    }

    xfer_ctx->valid_buflen = valid_buflen;
    return (uint8_t **)&xfer_ctx->buffer;
}

int
store_fbox(int fbox_inout, uint8_t ** buffer)
{
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)((uintptr_t)buffer
                             - offsetof(xfer_context_t, buffer));
    uint8_t * fbox_buffer;
    int ret = -1, len = xfer_ctx->valid_buflen;
    int * fbox_xfer_ptr = (fbox_inout == UCAFS_FBOX_READ) ? &xfer_ctx->fbox_rd
                                                          : &xfer_ctx->fbox_wr;

    /* make sure we are not reading past the buffer */
    if (*fbox_xfer_ptr + len > xfer_ctx->fbox->fbox_len) {
        slog(0, SLOG_FATAL, "overrunning fbox buffer");
        return -1;
    }

    fbox_buffer = (uint8_t *)xfer_ctx->fbox + xfer_ctx->fbox_xfer;

    if (fbox_inout == UCAFS_FBOX_READ) {
        memcpy(xfer_ctx->buffer, fbox_buffer, len);
    } else {
        memcpy(fbox_buffer, xfer_ctx->buffer, len);
    }

    *fbox_xfer_ptr += len;

    /* if we have gotten enough */
    if (*fbox_xfer_ptr == xfer_ctx->fbox->fbox_len) {
#ifdef UCAFS_SGX
        ecall_store_start(global_eid, &ret, xfer_ctx);
        if (ret) {
            slog(0, SLOG_FATAL, "enclave error");
            goto out;
        }
#endif
    }

    ret = 0;
out:
    if (ret) {
        free_xfer_context(xfer_ctx);
    }

    return ret;
}

int
store_data(uint8_t ** buffer)
{
    int ret = -1;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)((uintptr_t)buffer
                             - offsetof(xfer_context_t, buffer));

#ifdef UCAFS_SGX
    ecall_store_crypto(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_FATAL, "enclave error");
        goto out;
    }
#endif

    ret = 0;
out:
    if (ret) {
        free_xfer_context(xfer_ctx);
    }

    return ret;
}

int
store_finish(int id)
{
    int ret = 0;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        slog(0, SLOG_ERROR, "xfer_ctx id=%d not found", id);
        return -1;
    }

#ifdef UCAFS_SGX
    ecall_store_finish(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_ERROR, "enclave reports error");
        // TODO have proper handling here
    }
#endif

    free_xfer_context(xfer_ctx);
    return ret;
}
