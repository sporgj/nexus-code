#include <cstdint>
#include <vector>
#include <glog/logging.h>
#include <iostream>

#include "fileops.h"
#include "filebox.h"
#include "dirops.h"
#include "utils.h"
#include "afsx_hdr.h"
#include "enclave_common.h"

using std::vector;

#define CAPACITY 10

static int counter = 0;
// TODO switch to different structure
static vector<fop_ctx_t *> ctx_array(0, nullptr);

/**
 * Starts a file upload/download operation
 *
 * retptr is set depending on cause of the failulre. -1 = file not found which
 *might
 * not be a failure. -2 implies cryptographic operations may have failed
 *
 * returns nullptr on failure, retptr set.
 */
fop_ctx_t * fileops_start(int op, char * fpath, uint32_t max_chunk_size,
                          uint64_t filelength, uint32_t * padded_len,
                          int * retptr)
{
    uint32_t seg_id = 0;
    int ret;
    /* get the corresponding filebox, else return 0 */
    FileBox * fbox = FileBox::from_afs_file(fpath);
    if (fbox == nullptr) {
        *retptr = -1;
        return nullptr;
    }

    // get file encryption info
    // only one cryptographic information for now
    file_crypto_t * f_seal = fbox->segment_crypto(seg_id);

    fop_ctx_t * ctx = new fop_ctx_t;
    ctx->op = op;
    ctx->buffer = (char *)operator new(max_chunk_size);
    ctx->done = 0;
    ctx->cap = max_chunk_size;
    ctx->total = filelength;
    ctx->id = counter++;
    ctx->seg_id = seg_id;
    ctx->path = strdup(fpath);

    // call the enclave setup
    if (ecall_init_crypto(global_eid, &ret, ctx, f_seal)) {
        free(ctx->path);
        delete ctx->buffer;
        delete ctx;
        *retptr = -2;
        return nullptr;
    }

    *padded_len = CRYPTO_CEIL_TO_BLKSIZE(ctx->total);

    ctx_array.push_back(ctx);
    *retptr = 0;
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
    int ret;
    uint8_t * ptr = (uint8_t *)ctx->buffer;
    hexdump(ptr, ctx->len > 32 ? 32 : ctx->len);

    ecall_crypt_data(global_eid, &ret, ctx);
    if (ret) {
        goto out;
    }

    hexdump((uint8_t *)ctx->buffer, ctx->len > 32 ? 32 : ctx->len);

    ctx->done += ctx->len;
out:
    return ret;
}

/**
 * Might return -1 for entries not found in the fileops array. if -2, then
 * SGX enclave failed somehow (eg. MAC check failed). To be handled by caller
 */
int fileops_finish(uint32_t id, int * op, uint32_t * done)
{
    FileBox * fbox;
    file_crypto_t * fseal;
    int ret = -2;

    auto ctx_iter = ctx_array.begin();
    while (ctx_iter != ctx_array.end()) {
        auto & ctx = *ctx_iter;
        if (ctx->id == id) {
            *done = ctx->done;
            *op = ctx->op;

            fbox = FileBox::from_afs_file(ctx->path);
            if (fbox
                && (fseal = fbox->segment_crypto(ctx->seg_id)) != nullptr) {

                // complete the cryptographic operation
                ecall_finish_crypto(global_eid, &ret, ctx, fseal);
                if (ret) {
                    std::cout << "sgx failed: " << ctx->id << std::endl;
                    ret = -2;
                }
            }
            ctx_array.erase(ctx_iter);
            free(ctx->path);
            delete ctx->buffer;
            delete ctx;
            return ret;
        }
        ctx_iter++;
    }
    return -1;
}
