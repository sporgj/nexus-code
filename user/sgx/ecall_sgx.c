#include "enclave_private.h"
#include "seqptrmap.h"

#include "../types.h"

#include <string.h>

#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;

typedef struct {
    file_crypto_t crypto_data;
    crypto_iv_t iv;
    mbedtls_aes_context aes_ctx;
    mbedtls_md_context_t hmac_ctx;
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
 *
 * @param fcrypto is the cryptographic information. Copied into the enclave
 * @param f_ctx is the file context
 * @return 0 on success
 */
int ecall_init_crypto(fop_ctx_t * f_ctx, file_crypto_t * fcrypto)
{
    int error = E_ERROR_CRYPTO;
    crypto_ctx_t __SECRET * __ctx
        = (crypto_ctx_t *)calloc(1, sizeof(crypto_ctx_t));
    if (__ctx == NULL) {
        return E_ERROR_CRYPTO;
    }

    /* copy the crypto data */
    memcpy(&__ctx->crypto_data, fcrypto, sizeof(file_crypto_t));
    memset(&__ctx->iv, 0, sizeof(crypto_iv_t));

    /* initialize the crypto ccontext*/
    mbedtls_md_init(&__ctx->hmac_ctx);
    if (mbedtls_md_setup(&__ctx->hmac_ctx,
                         mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1)) {
        goto out;
    }

    if (mbedtls_md_hmac_starts(&__ctx->hmac_ctx,
                               (uint8_t *)&__ctx->crypto_data.skey,
                               CRYPTO_MAC_KEY_SIZE_BITS)) {
        goto out;
    }

    mbedtls_aes_init(&__ctx->aes_ctx);
    if (f_ctx->op == UCPRIV_ENCRYPT) {
        if (mbedtls_aes_setkey_enc(&__ctx->aes_ctx,
                                   (uint8_t *)&__ctx->crypto_data.ekey,
                                   CRYPTO_AES_KEY_SIZE_BITS)) {
            goto out;
        }
    } else {
        if (mbedtls_aes_setkey_dec(&__ctx->aes_ctx,
                                   (uint8_t *)&__ctx->crypto_data.ekey,
                                   CRYPTO_AES_KEY_SIZE_BITS)) {
            goto out;
        }
    }

    if ((f_ctx->crypto_id = seqptrmap_add(crypto_hashmap, __ctx)) == -1) {
        error = E_ERROR_ERROR;
        goto out;
    }

    error = E_SUCCESS;
out:
    if (error) {
        free(__ctx);
    }
    return error;
}

int ecall_crypt_data(fop_ctx_t * f_ctx)
{
    int error = E_ERROR_ERROR;
    size_t len, nbytes, i;
    crypto_iv_t iv;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    uint8_t * p_input;
    crypto_ctx_t __SECRET * __ctx
        = seqptrmap_get(crypto_hashmap, f_ctx->crypto_id);
    if (__ctx == NULL) {
        goto out;
    }

    p_input = (uint8_t *)calloc(1, E_CRYPTO_BUFFER_LEN);
    if (p_input == NULL) {
        error = E_ERROR_ALLOC;
        goto out;
    }

    len = f_ctx->len;
    memcpy(&iv, &__ctx->iv, sizeof(crypto_iv_t));

    aes_ctx = &__ctx->aes_ctx;
    hmac_ctx = &__ctx->hmac_ctx;

    for (i = 0; i < len; i += E_CRYPTO_BUFFER_LEN) {
        nbytes = (len - i) > E_CRYPTO_BUFFER_LEN ? E_CRYPTO_BUFFER_LEN
                                                 : (len - i);
        memcpy(p_input, f_ctx->buffer + i, nbytes);

        if (f_ctx->op == UCPRIV_ENCRYPT) {
            mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_ENCRYPT, nbytes,
                                  (uint8_t *)&iv, p_input, p_input);
        }

        mbedtls_md_hmac_update(hmac_ctx, p_input, nbytes);

        if (f_ctx->op == UCPRIV_DECRYPT) {
            mbedtls_aes_crypt_cbc(aes_ctx, MBEDTLS_AES_DECRYPT, nbytes,
                                  (uint8_t *)&iv, p_input, p_input);
        }

        memcpy(f_ctx->buffer + i, p_input, nbytes);
    }

    error = E_SUCCESS;
out:
    return error;
}

int ecall_finish_crypto(fop_ctx_t * f_ctx, file_crypto_t * fcrypto)
{
    int error = E_ERROR_ERROR;
    crypto_mac_t mac;
    crypto_ctx_t __SECRET * __ctx
        = seqptrmap_get(crypto_hashmap, f_ctx->crypto_id);
    if (__ctx == NULL) {
        goto out;
    }

    mbedtls_aes_free(&__ctx->aes_ctx);

    /* close the crypto context and verify the mac */
    mbedtls_md_hmac_finish(&__ctx->hmac_ctx, (uint8_t *)&mac);
    if (f_ctx->op == UCPRIV_DECRYPT
        && memcmp(&mac, &__ctx->crypto_data.mac, sizeof(crypto_mac_t))) {
        goto out;
    }

    mbedtls_md_free(&__ctx->hmac_ctx);

    // TODO seal the keys before sending

    memcpy(fcrypto, &__ctx->crypto_data, sizeof(file_crypto_t));
    memset(__ctx, 0, sizeof(file_crypto_t));
    error = E_SUCCESS;
out:
    free(__ctx);
    seqptrmap_delete(crypto_hashmap, f_ctx->crypto_id);
    return error;
}
