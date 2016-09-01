#pragma once

typedef struct {
    int op;
    uint32_t id;
    char * buffer;
    uint32_t done;
    uint32_t len;
    uint32_t cap;
    uint64_t total;
} fop_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

fop_ctx_t * fileops_start(int op, char * fpath, uint32_t max_chunk_size,
                          uint64_t filelength, int * retptr);

fop_ctx_t * fileops_get_context(uint32_t id);

int fileops_process_data(fop_ctx_t * ctx);

int fileops_finish(uint32_t id, int * op, uint32_t * done);

#ifdef __cplusplus
}
#endif
