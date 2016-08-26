#include <cstdint>
#include <vector>
#include <glog/logging.h>

#include "fileops.h"
#include "dirops.h"
#include "utils.h"

using std::vector;

#define CAPACITY 10

int upload_counter = 0, download_counter = 0;
vector<fop_ctx_t *> upload_list(0, nullptr), download_list(0, nullptr);

inline static fop_ctx_t * __new_ctx(vector<fop_ctx_t *> * ctx_array,
                                    int * counter, char * fpath,
                                    uint32_t max_chunk_size,
                                    uint64_t filelength)
{
    if (ctx_array->size() >= CAPACITY) {
        return nullptr;
    }

    // check if the dirnode knows about this file
    {
        char * temp;
        int ret = fops_plain2code(fpath, &temp);
        if (ret) {
            // then we don't have anything
            return nullptr;
        }
    }

    fop_ctx_t * ctx = new fop_ctx_t;
    ctx->buffer = (char *)operator new(max_chunk_size);
    ctx->done = 0;
    ctx->cap = max_chunk_size;
    ctx->total = filelength;
    ctx->id = *counter;
    *counter = *counter + 1;
    ctx_array->push_back(ctx);
    return ctx;
}

inline static int __rm_ctx(vector<fop_ctx_t *> * context_array_ptr, uint32_t id)
{
    vector<fop_ctx_t *> & context_array = *context_array_ptr;
    for (uint32_t i = 0; i < context_array.size(); i++) {
        if (context_array[i] && context_array[i]->id == id) {
            context_array[i] = nullptr;
            return 0;
        }
    }
    return -1;
}

inline static fop_ctx_t * __get_ctx(vector<fop_ctx_t *> * ctx_array_ptr,
                                    uint32_t id)
{
    vector<fop_ctx_t *> & ctx_array = *ctx_array_ptr;
    for (uint32_t i = 0; i < ctx_array.size(); i++) {
        if (ctx_array[i] && ctx_array[i]->id == id) {
            return ctx_array[i];
        }
    }
    return nullptr;
}

fop_ctx_t * start_upload(char * fpath, uint32_t max_chunk_size,
                         uint64_t filelength)
{
    return __new_ctx(&upload_list, &upload_counter, fpath, max_chunk_size,
                     filelength);
}

fop_ctx_t * start_download(char * fpath, uint32_t max_chunk_size,
                           uint64_t filelength)
{
    return __new_ctx(&download_list, &download_counter, fpath, max_chunk_size,
                     filelength);
}

fop_ctx_t * get_upload_buffer(uint32_t id)
{
    return __get_ctx(&upload_list, id);
}

fop_ctx_t * get_download_buffer(uint32_t id)
{
    return __get_ctx(&download_list, id);
}

int process_upload_data(fop_ctx_t * ctx)
{
    uint8_t * ptr = (uint8_t *)ctx->buffer;
    // FAKE encryption
    for (uint32_t i = 0; i < ctx->len; i++) {
        *ptr = *ptr + 1;
        ptr++;
    }

    ctx->done += ctx->len;

    return 0;
}

int process_download_data(fop_ctx_t * ctx)
{
    uint8_t * ptr = (uint8_t *)ctx->buffer;
    // FAKE encryption
    for (uint32_t i = 0; i < ctx->len; i++) {
        *ptr = *ptr - 1;
        ptr++;
    }

    return 0;
}

int finish_upload(fop_ctx_t * ctx) { return __rm_ctx(&upload_list, ctx->id); }

int finish_download(fop_ctx_t * ctx)
{
    return __rm_ctx(&download_list, ctx->id);
}
