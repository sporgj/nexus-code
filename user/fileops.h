#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

xfer_context_t * fileops_start(int op, char * fpath, uint32_t max_chunk_size,
                          uint32_t filelength, uint32_t * padded_len,
                          int * retptr);

xfer_context_t * fileops_get_context(uint32_t id);

int fileops_process_data(xfer_context_t * ctx);

int fileops_finish(uint32_t id, int * op, uint32_t * done);

#ifdef __cplusplus
}
#endif
