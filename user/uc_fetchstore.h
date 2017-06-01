#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "uc_filebox.h"

/* data transfer for fbox */
typedef struct {
    uc_xfer_op_t xfer_op;
    int xfer_id, enclave_crypto_id, chunk_num;
    char * buffer, * path;
    uint32_t buflen, valid_buflen, chunk_left, xfer_size, offset, total_len;
    filebox_chunk_t * chunk; // the current chunk
    uc_filebox_t * filebox;
} xfer_context_t;

int
fetchstore_init(xfer_req_t * rq, char * fpath, xfer_rsp_t * rp);

int
fetchstore_run(int id, size_t valid_buflen);

int
fetchstore_finish(int id);

#ifdef __cplusplus
}
#endif
