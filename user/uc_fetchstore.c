#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "enclave_u.h"

#include "third/log.h"
#include "third/sds.h"
#include "third/seqptrmap.h"

#include "uc_dirnode.h"
#include "uc_fetchstore.h"
#include "uc_filebox.h"
#include "uc_sgx.h"
#include "uc_utils.h"
#include "uc_vfs.h"

static struct seqptrmap * xfer_context_array = NULL;

static void
free_xfer_context(xfer_context_t * xfer_ctx)
{
    if (xfer_ctx->xfer_id != -1) {
        seqptrmap_delete(xfer_context_array, xfer_ctx->xfer_id);
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
fetchstore_init(xfer_req_t * rq, char * fpath, xfer_rsp_t * rp)
{
    int ret = -1;
    xfer_context_t * xfer_ctx = NULL;
    const shadow_t * shdw_name;
    uc_filebox_t * filebox;
    ucafs_entry_type atype;
    int chunk_count;

    /* TODO move this to an init function */
    if (xfer_context_array == NULL) {
        xfer_context_array = seqptrmap_init();
    }

    /* lets find the dirnode object first */
    filebox = dcache_filebox(fpath, UCAFS_FBOX_SIZE(rq->file_size), rq->op);
    if (filebox == NULL) {
        log_error("finding filebox failed: '%s'", fpath);
        return ret;
    }

    xfer_ctx = (xfer_context_t *)calloc(1, sizeof(xfer_context_t));
    if (xfer_ctx == NULL) {
        log_fatal("fileops - memory allocation failed");
        goto out;
    }

    /* initialize our xfer context data */
    xfer_ctx->xfer_id = -1;
    xfer_ctx->xfer_op = rq->op;
    xfer_ctx->completed = 0;
    xfer_ctx->buflen = global_xfer_buflen;
    xfer_ctx->offset = rq->offset;
    xfer_ctx->total_len = rq->file_size;
    xfer_ctx->path = strdup(fpath);
    xfer_ctx->chunk_num = UCAFS_CHUNK_NUM(rq->offset);
    xfer_ctx->fbox = filebox_fbox(filebox);
    xfer_ctx->filebox = filebox;
    xfer_ctx->buffer = global_xfer_addr;

    xfer_ctx->xfer_id = seqptrmap_add(xfer_context_array, xfer_ctx);
    if (xfer_ctx->xfer_id == -1) {
        // TODO delete context from enclave space
        log_error("fileops - Adding to list failed");
        goto out;
    }

#ifdef UCAFS_SGX
    ecall_fetchstore_init(global_eid, &ret, xfer_ctx);
    if (ret) {
        log_error("Enclave error");
        goto out;
    }

    ecall_fetchstore_start(global_eid, &ret, xfer_ctx);
    if (ret) {
        log_fatal("enclave error");
        goto out;
    }
#endif

    /* set the response */
    *rp = (xfer_rsp_t){.xfer_id = xfer_ctx->xfer_id };

    ret = 0;
out:
    if (ret) {
        free_xfer_context(xfer_ctx);
    }

    return ret;
}

int
fetchstore_run(int id, size_t valid_buflen)
{
    int ret = -1;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        log_warn("xfer_ctx id=%d not found", id);
        return -1;
    }

    xfer_ctx->valid_buflen = valid_buflen;

#ifdef UCAFS_SGX
    ecall_fetchstore_crypto(global_eid, &ret, xfer_ctx);
    if (ret) {
        log_fatal("enclave error (%s)", xfer_ctx->filebox->fbox_path);
        goto out;
    }
#endif

    ret = 0;
out:
    return ret;
}

int
fetchstore_finish(int id)
{
    int ret = -1;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        log_error("xfer_ctx id=%d not found", id);
        return -1;
    }

#ifdef UCAFS_SGX
    ecall_fetchstore_finish(global_eid, &ret, xfer_ctx);
    if (ret) {
        log_error("enclave reports error (%d): %s", ret,
                xfer_ctx->filebox->fbox_path);
        // TODO have proper handling here
        goto out;
    }
#endif

    if (!filebox_flush(xfer_ctx->filebox)) {
        log_error("committing the filebox to disk failed");
        goto out;
    }

    ret = 0;
out:
    free_xfer_context(xfer_ctx);
    return ret;
}
