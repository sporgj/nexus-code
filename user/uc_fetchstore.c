#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "enclave_u.h"

#include "third/sds.h"
#include "third/seqptrmap.h"
#include "third/slog.h"

#include "uc_dcache.h"
#include "uc_dirnode.h"
#include "uc_fetchstore.h"
#include "uc_filebox.h"
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

    if (xfer_ctx->filebox) {
        filebox_free(xfer_ctx->filebox);
    }

    if (xfer_ctx->path) {
        free(xfer_ctx->path);
    }

    free(xfer_ctx);
}

int
fetchstore_start(uc_xfer_op_t op,
                 char * fpath,
                 uint16_t max_xfer_size,
                 uint32_t offset,
                 uint32_t file_size,
                 int old_fbox_len,
                 int * xfer_id,
                 int * new_fbox_len)
{
    int ret = -1;
    sds fname_sds = NULL;
    xfer_context_t * xfer_ctx = NULL;
    const shadow_t * shdw_name;
    uc_filebox_t * filebox;
    ucafs_entry_type atype;
    int chunk_count;

    /* lets find the dirnode object first */
    filebox = dcache_get_filebox(fpath, UCAFS_FBOX_SIZE(file_size));
    if (filebox == NULL) {
        slog(0, SLOG_ERROR, "finding filebox failed: '%s'", fpath);
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
    xfer_ctx->xfer_op = op;
    xfer_ctx->completed = 0;
    xfer_ctx->buflen = max_xfer_size;
    xfer_ctx->offset = offset;
    xfer_ctx->total_len = file_size;
    xfer_ctx->path = strdup(fpath);
    xfer_ctx->chunk_num = UCAFS_CHUNK_NUM(offset);
    xfer_ctx->fbox = filebox_fbox(filebox);
    xfer_ctx->filebox = filebox;

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
    ecall_fetchstore_init(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_ERROR, "Enclave error");
        goto out;
    }

    ecall_fetchstore_start(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_FATAL, "enclave error");
        goto out;
    }
#endif

    *new_fbox_len = 0; // fbox->fbox_len;
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

    return ret;
}

uint8_t **
fetchstore_get_buffer(int id, size_t valid_buflen)
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
fetchstore_data(uint8_t ** buffer)
{
    int ret = -1;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)((uintptr_t)buffer
                             - offsetof(xfer_context_t, buffer));

#ifdef UCAFS_SGX
    ecall_fetchstore_crypto(global_eid, &ret, xfer_ctx);
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
fetchstore_finish(int id)
{
    int ret = -1;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        slog(0, SLOG_ERROR, "xfer_ctx id=%d not found", id);
        return -1;
    }

#ifdef UCAFS_SGX
    ecall_fetchstore_finish(global_eid, &ret, xfer_ctx);
    if (ret) {
        slog(0, SLOG_ERROR, "enclave reports error");
        // TODO have proper handling here
        goto out;
    }
#endif

    if (!filebox_flush(xfer_ctx->filebox)) {
        slog(0, SLOG_ERROR, "committing the filebox to disk failed");
        goto out;
    }

    ret = 0;
out:
    free_xfer_context(xfer_ctx);
    return ret;
}
