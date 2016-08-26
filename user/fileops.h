#pragma once

typedef struct {
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

/**
 * Sets up a context for a file upload
 * @param fpath is the file path
 * @param max_chunk_size is the maximum number of bytes that could be sent
 * @param filelength is the total length of the file to be uploaded
 * @return nullptr on failure
 */
fop_ctx_t * start_upload(char * fpath, uint32_t max_chunk_size, uint64_t filelength);
fop_ctx_t * start_download(char * fpath, uint32_t max_chunk_size, uint64_t filelength);

/**
 * Processes upload data. Before calling the function, set the data
 * in store_ctx->buffer and set the length correctly
 * @param store_ctx
 * @return 0 on success
 */
int process_upload_data(fop_ctx_t * store_ctx);
int process_download_data(fop_ctx_t * store_ctx);

/**
 * Cleans up the created structures
 * @param store_ctx is the context to cleanup
 * @return 0 on success
 */
int finish_upload(fop_ctx_t * store_ctx);
int finish_download(fop_ctx_t * store_ctx);

fop_ctx_t * get_upload_buffer(uint32_t id);
fop_ctx_t * get_download_buffer(uint32_t id);

#ifdef __cplusplus
}
#endif
