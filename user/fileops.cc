#include <cstdint>
#include <vector>
#include <glog/logging.h>
#include <iostream>

#include "fileops.h"
#include "dirops.h"
#include "utils.h"
#include "afsx_hdr.h"

using std::vector;

#define CAPACITY 10

static int counter = 0;
// TODO switch to different structure
static vector<fop_ctx_t *> ctx_array(0, nullptr);

fop_ctx_t * fileops_start(int op, char * fpath, uint32_t max_chunk_size,
                          uint64_t filelength, int * retptr)
{
    // check if the dirnode knows about this file
    char * temp;
    std::cout << fpath << std::endl;
    int ret = fops_plain2code(fpath, &temp);
    if (ret) {
        *retptr = -1;
        // then we don't have anything
        return nullptr;
    }
    *retptr = 0;

    fop_ctx_t * ctx = new fop_ctx_t;
    ctx->op = op;
    ctx->buffer = (char *)operator new(max_chunk_size);
    ctx->done = 0;
    ctx->cap = max_chunk_size;
    ctx->total = filelength;
    ctx->id = counter++;
    ctx_array.push_back(ctx);
    return ctx;
}

fop_ctx_t * fileops_get_context(uint32_t id)
{
    for (uint32_t i = 0; i < ctx_array.size(); i++) {
        if (ctx_array[i] && ctx_array[i]->id == id) {
            return ctx_array[i];
        }
    }
    return nullptr;
}

int fileops_process_data(fop_ctx_t * ctx)
{
    uint8_t * ptr = (uint8_t *)ctx->buffer;
    hexdump(ptr, ctx->len > 32 ? 32 : ctx->len);
    // FAKE encryption
    for (uint32_t i = 0; i < ctx->len; i++) {
        *ptr = (ctx->op == UCAFS_WRITEOP) ? (*ptr - 1) : (*ptr + 1);
        ptr++;
    }
    hexdump((uint8_t *)ctx->buffer, ctx->len > 32 ? 32 : ctx->len);

    ctx->done += ctx->len;

    return 0;
}

int fileops_finish(uint32_t id, int * op, uint32_t * done)
{
    auto ctx_iter = ctx_array.begin();
    while (ctx_iter != ctx_array.end()) {
        auto &ctx = *ctx_iter;
        if (ctx->id == id) {
            *done = ctx->done;
            *op = ctx->op;

            ctx_array.erase(ctx_iter);
            return 0;
        }
        ctx_iter++;
    }
    return -1;
}
