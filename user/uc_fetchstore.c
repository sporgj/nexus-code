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
fetchstore_init(xfer_req_t * req, char * fpath, xfer_rsp_t * rsp)
{
    int ret = -1;
    xfer_context_t * xfer_ctx;
    uc_filebox_t * filebox;

    if (xfer_context_array == NULL) {
        xfer_context_array = seqptrmap_init();
    }

    /* lets find the dirnode object first */
    filebox = dcache_filebox(fpath, req->op);
    if (filebox == NULL) {
        log_error("finding filebox failed: '%s'", fpath);
        return ret;
    }

    xfer_ctx = (xfer_context_t *)calloc(1, sizeof(xfer_context_t));
    if (xfer_ctx == NULL) {
        log_fatal("fileops - memory allocation failed");
        goto out;
    }

    /* initialize the xfer content */
    xfer_ctx->enclave_crypto_id = -1;
    xfer_ctx->xfer_op = req->op;
    xfer_ctx->offset = req->offset;
    xfer_ctx->total_len = req->file_size;
    xfer_ctx->xfer_size = req->xfer_size;

    /* set the buffer and its maximum size */
    xfer_ctx->buffer = (uint8_t *)global_xfer_addr;
    xfer_ctx->buflen = global_xfer_buflen;

    xfer_ctx->path = strdup(fpath);
    xfer_ctx->filebox = filebox;

    /* add it to the context array */
    xfer_ctx->xfer_id = seqptrmap_add(xfer_context_array, xfer_ctx);
    if (xfer_ctx->xfer_id == -1) {
        // TODO delete context from enclave space
        log_error("fileops - Adding to list failed");
        goto out;
    }

    filebox_set_size(filebox, req->file_size);

    /* set the response */
    *rsp = (xfer_rsp_t){.xfer_id = xfer_ctx->xfer_id };

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
    int ret = 0;
    xfer_context_t * xfer_ctx
        = (xfer_context_t *)seqptrmap_get(xfer_context_array, id);
    if (xfer_ctx == NULL) {
        log_error("xfer_ctx id=%d not found", id);
        return -1;
    }

    xfer_ctx->valid_buflen = valid_buflen;

#ifdef UCAFS_SGX
    if (xfer_ctx->enclave_crypto_id == -1) {
        /* calculate chunk left */
        xfer_ctx->chunk_num = UCAFS_CHUNK_NUM(xfer_ctx->offset);
        xfer_ctx->chunk_left = MIN(xfer_ctx->xfer_size, UCAFS_CHUNK_SIZE);
        /* get the chunk information */
        xfer_ctx->chunk
            = filebox_get_chunk(xfer_ctx->filebox, xfer_ctx->chunk_num);

        if (xfer_ctx->chunk == NULL) {
            log_error("problem getting chunknum=%d", xfer_ctx->chunk_num);
            return 0;
        }

        ecall_xfer_init(global_eid, &ret, xfer_ctx);
        if (ret) {
            log_error("enclave error: initializing transfer failed (%s)",
                    xfer_ctx->path);
            goto out;
        }
    }

    /* call the enclave for encryption */
    ecall_xfer_crypto(global_eid, &ret, xfer_ctx);
    if (ret) {
        log_error("enclave encryption error (%d) (%s)", ret,
                xfer_ctx->path);
        goto out;
    }

    /* update the amount of data left to be encrypted */
    xfer_ctx->chunk_left -= valid_buflen;
    xfer_ctx->offset += valid_buflen;
    xfer_ctx->xfer_size -= valid_buflen;

    /* how much of the chunk do we have left */
    if (xfer_ctx->chunk_left == 0) {
        ecall_xfer_finish(global_eid, &ret, xfer_ctx);
        if (ret) {
            log_error("enclave error: finishing transfer (%d) (%s)", ret,
                    xfer_ctx->path);
            goto out;
        }
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

    if (xfer_ctx->xfer_op == UCAFS_STORE && !filebox_flush(xfer_ctx->filebox)) {
        log_error("committing the filebox to disk failed");
        goto out;
    }

    ret = 0;
out:
    free_xfer_context(xfer_ctx);
    return ret;
}
