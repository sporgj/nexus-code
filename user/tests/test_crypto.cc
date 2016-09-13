#include "defs.h"
#include <cstdlib>
#include <iostream>
#include <ctime>
#include <sgx_urts.h>

#define NUMBER_OF_TESTS 5
#define MAX_BUFLEN  2137
#define CHUNK_SIZE 250
#define ENCLAVE_FILENAME "../sgx/enclave.signed.so"

using std::cout;
using std::endl;

sgx_enclave_id_t global_eid = 0;

static size_t generate(size_t len, size_t plen, uint8_t ** buf1,
                       uint8_t ** buf2)
{
    uint8_t * buffer1 = new uint8_t[plen], *buffer2 = new uint8_t[plen];

    for (size_t i = 0; i < len; i++) {
        buffer2[i] = buffer1[i] = std::rand() % UCHAR_MAX;
    }

    *buf1 = buffer1;
    *buf2 = buffer2;

    return len;
}

static xfer_context_t * get_fop(size_t len)
{
    xfer_context_t * ctx = new xfer_context_t;
    ctx->completed = 0;
    ctx->buflen = CHUNK_SIZE;
    ctx->raw_len = len;
    ctx->valid_buflen = len; // TODO
    ctx->id = 1;

    return ctx;
}

int test_crypto()
{
    int ret;
    uint8_t * buf1, *buf2;
    size_t len = std::rand() % MAX_BUFLEN;

    crypto_context_t * fcrypto = new crypto_context_t;
    memset(fcrypto, 0, sizeof(crypto_context_t));

    xfer_context_t * fop_ctx = get_fop(len);
    fop_ctx->op = UCPRIV_ENCRYPT;
    ecall_init_crypto(global_eid, &ret, fop_ctx, fcrypto);
    if (ret) {
        cout << "Could not initialize the crypto" << endl;
        return -1;
    }

    /* 1 - Generate the stream */
    len = generate(len, fop_ctx->padded_len, &buf1, &buf2);
    cout << "Generated buffer (len=" << len << ", plen=" << fop_ctx->padded_len
         << ")" << endl;
    hexdump(buf1, (fop_ctx->padded_len > 32 ? 32 : fop_ctx->padded_len));

    fop_ctx->buffer = (char *)buf1;

    /* 2 - Encrypt the stream */
    cout << "Encrypting..." << endl;
    ecall_crypt_data(global_eid, &ret, fop_ctx);
    if (ret) {
        cout << "Encryption of data failed" << endl;
    }
    hexdump(buf1, (fop_ctx->padded_len > 32 ? 32 : fop_ctx->padded_len));

    ecall_finish_crypto(global_eid, &ret, fop_ctx, fcrypto);
    if (ret) {
        cout << "Finish crypto failed" << endl;
        return -1;
    }

    /* 3 - Decrypt the stream */
    fop_ctx->op = UCPRIV_DECRYPT;
    fop_ctx->valid_buflen = fop_ctx->padded_len;
    fop_ctx->completed = 0;
    cout << "Decrypting..." << endl;
    ecall_init_crypto(global_eid, &ret, fop_ctx, fcrypto);
    if (ret) {
        cout << "Init crypto" << endl;
        return -1;
    }

    ecall_crypt_data(global_eid, &ret, fop_ctx);
    if (ret) {
        cout << "Encryption of data failed" << endl;
    }
    hexdump(buf1, (fop_ctx->padded_len > 32 ? 32 : fop_ctx->padded_len));

    ecall_finish_crypto(global_eid, &ret, fop_ctx, fcrypto);
    if (ret) {
        cout << "finish crypto failed on decryption" << endl;
        return -1;
    }

    /* 4 - Compare with the original */
    return 0;
}

int main()
{
    int ret, updated;
    sgx_launch_token_t token;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        cout << "Could not open enclave: " << ENCLAVE_FILENAME
             << ", ret=" << ret << endl;
        return -1;
    }

    // initialize
    ecall_init_enclave(global_eid, &ret);
    if (ret) {
        cout << "Initializing enclave failed" << endl;
        return -1;
    }

    cout << "Initialized enclave" << endl;

    std::srand(std::time(0));
    test_crypto();
    return 0;
}
