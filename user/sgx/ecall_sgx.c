#include "enclave_private.h"
#include "seqptrmap.h"

#include "../uc_types.h"

#include <string.h>

#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>

sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;

typedef struct {
    crypto_context_t crypto_data;
    crypto_iv_t iv;
    mbedtls_gcm_context gcm_ctx;
    uint8_t * p_input;
    uint8_t * p_output;
} crypto_ctx_t;

struct seqptrmap * crypto_hashmap = NULL;

int ecall_init_enclave()
{
    sgx_key_request_t request;
    sgx_status_t status;
    int ret;

    memset(&request, 0, sizeof(sgx_key_request_t));
    request.key_name = SGX_KEYSELECT_SEAL;
    request.key_policy = SGX_KEYPOLICY_MRSIGNER;
    request.attribute_mask.flags = 0xfffffffffffffff3ULL;
    request.attribute_mask.xfrm = 0;

    status = sgx_get_key(&request, &__enclave_encryption_key__);
    if (status != SGX_SUCCESS) {
        ret = E_ERROR_KEYINIT;
        goto out;
    }

    if ((crypto_hashmap = seqptrmap_init()) == NULL) {
        ret = E_ERROR_HASHMAP;
        goto out;
    }

    ret = E_SUCCESS;
out:
    return ret;
}

/**
 * Starts the file crypto
 * @return 0 on success
 */
int ecall_init_crypto(xfer_context_t * xfer_ctx, crypto_context_t * fcrypto)
{
    int error = E_ERROR_CRYPTO;
    crypto_ctx_t __SECRET * __ctx;
    mbedtls_gcm_context * gcm_ctx;

    if ((__ctx = (crypto_ctx_t *)calloc(1, sizeof(crypto_ctx_t))) == NULL) {
        return E_ERROR_CRYPTO;
    }

    /* copy the crypto data */
    memcpy(&__ctx->crypto_data, fcrypto, sizeof(crypto_context_t));
    if (xfer_ctx->op == UCPRIV_ENCRYPT) {
        sgx_read_rand((uint8_t *)&__ctx->iv, sizeof(crypto_iv_t));
        memcpy(&__ctx->crypto_data.iv, &__ctx->iv, sizeof(crypto_iv_t));
    } else {
        memcpy(&__ctx->iv, &__ctx->crypto_data.iv, sizeof(crypto_iv_t));
    }

    gcm_ctx = &__ctx->gcm_ctx;
    mbedtls_gcm_init(gcm_ctx);
    if (mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&__ctx->crypto_data.ekey,
                           CRYPTO_AES_KEY_SIZE_BITS)) {
        goto out;
    }

    /* intialize gcm */
    mbedtls_gcm_starts(gcm_ctx,
                       xfer_ctx->op == UCPRIV_ENCRYPT ? MBEDTLS_GCM_ENCRYPT
                                                      : MBEDTLS_GCM_DECRYPT,
                       (uint8_t *)&__ctx->iv, sizeof(crypto_iv_t), NULL, 0);

    if ((xfer_ctx->crypto_id = seqptrmap_add(crypto_hashmap, __ctx)) == -1) {
        error = E_ERROR_ERROR;
        goto out;
    }

    __ctx->p_input = (uint8_t *)calloc(1, E_CRYPTO_BUFFER_LEN);
    if (__ctx->p_input == NULL) {
        error = E_ERROR_ALLOC;
        goto out;
    }

    /* XXX, a possible optimisation here. On decrypt, the output only needs to
     * trail by 128 bits. */
    if (xfer_ctx->op == UCPRIV_DECRYPT) {
        __ctx->p_output = (uint8_t *)calloc(1, E_CRYPTO_BUFFER_LEN);
        if (__ctx->p_output == NULL) {
            error = E_ERROR_ALLOC;
            goto out;
        }
    } else {
        __ctx->p_output = __ctx->p_input;
    }

    error = E_SUCCESS;
out:
    if (error) {
        if (__ctx->p_input)
            free(__ctx->p_input);
        if (xfer_ctx->op == UCPRIV_DECRYPT)
            free(__ctx->p_output);
        free(__ctx);
    }
    return error;
}

int ecall_crypt_data(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, bytes_left;
    size_t nbytes;
    mbedtls_gcm_context * gcm_ctx;
    uint8_t * p_in, *p_out, *p_buf, *iv;
    crypto_ctx_t __SECRET * __ctx;

    if ((__ctx = seqptrmap_get(crypto_hashmap, xfer_ctx->crypto_id)) == NULL) {
        goto out;
    }

    gcm_ctx = &__ctx->gcm_ctx;
    p_in = __ctx->p_input;
    p_out = __ctx->p_output;
    p_buf = xfer_ctx->buffer;

    bytes_left = xfer_ctx->valid_buflen;
    while (bytes_left > 0) {
        nbytes = bytes_left > E_CRYPTO_BUFFER_LEN ? E_CRYPTO_BUFFER_LEN
                                                  : bytes_left;
        memcpy(p_in, p_buf, nbytes);
        mbedtls_gcm_update(gcm_ctx, nbytes, p_in, p_out);
        memcpy(p_buf, p_out, nbytes);

        bytes_left -= nbytes;
        p_buf += nbytes;
    }

    // TODO clear the p_in & p_out buffers

    error = E_SUCCESS;
out:
    return error;
}

int ecall_finish_crypto(xfer_context_t * xfer_ctx, crypto_context_t * fcrypto)
{
    int error = E_ERROR_ERROR;
    crypto_tag_t tag, *ctx_tag;
    crypto_ctx_t __SECRET * __ctx;

    if ((__ctx = seqptrmap_get(crypto_hashmap, xfer_ctx->crypto_id)) == NULL) {
        goto out;
    }

    ctx_tag = &__ctx->crypto_data.mac;

    /* close the crypto context and verify the mac */
    mbedtls_gcm_finish(&__ctx->gcm_ctx, (uint8_t *)&tag, sizeof(crypto_tag_t));
    if (xfer_ctx->op == UCPRIV_DECRYPT
        && memcmp(&tag, ctx_tag, sizeof(crypto_tag_t))) {
        goto out;
    } else {
        memcpy(ctx_tag, &tag, sizeof(crypto_tag_t));
    }

    mbedtls_gcm_free(&__ctx->gcm_ctx);

    // TODO seal the keys before sending

    memcpy(fcrypto, &__ctx->crypto_data, sizeof(crypto_context_t));
    memset(__ctx, 0, sizeof(crypto_ctx_t));
    error = E_SUCCESS;
out:
    free(__ctx->p_input);
    if (xfer_ctx->op == UCPRIV_DECRYPT) {
        free(__ctx->p_output);
    }
    free(__ctx);
    seqptrmap_delete(crypto_hashmap, xfer_ctx->crypto_id);
    return error;
}
