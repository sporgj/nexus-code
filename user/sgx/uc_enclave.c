#include "enclave_private.h"

int enclave_crypto_ekey(crypto_ekey_t * ekey, crypto_op_t op)
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (op == UCPRIV_ENCRYPT) {
        mbedtls_aes_setkey_enc(&ctx, (uint8_t *)&__enclave_encryption_key__,
                               CRYPTO_AES_KEY_SIZE_BITS);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (uint8_t *)ekey,
                              (uint8_t *)ekey);
    } else {
        mbedtls_aes_setkey_dec(&ctx, (uint8_t *)&__enclave_encryption_key__,
                               CRYPTO_AES_KEY_SIZE_BITS);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, (uint8_t *)ekey,
                              (uint8_t *)ekey);
    }

    mbedtls_aes_free(&ctx);

    return 0;
}

int
crypto_metadata(crypto_context_t * p_ctx,
                size_t protolen,
                uint8_t * data,
                crypto_op_t op)
{
    int error = E_ERROR_ERROR, bytes_left, len;
    mbedtls_gcm_context gcm_ctx;
    uint8_t * p_input = NULL, * p_output = NULL, * p_data;
    crypto_context_t crypto_ctx;
    crypto_tag_t gcm_mac;
    crypto_iv_t iv;
    crypto_ekey_t _CONFIDENTIAL * _ekey;

    p_input = (uint8_t *)malloc(E_CRYPTO_BUFFER_LEN);
    if (p_input == NULL) {
        return E_ERROR_ERROR;
    }

    /* XXX allocation only needed for decryption */
    p_output = (uint8_t *)malloc(E_CRYPTO_BUFFER_LEN);
    if (p_output == NULL) {
        free(p_input);
        return E_ERROR_ERROR;
    }

    /* gather the cryptographic information */
    _ekey = &crypto_ctx.ekey;
    memcpy(&crypto_ctx, p_ctx, sizeof(crypto_context_t));

    if (op == UCPRIV_ENCRYPT) {
        /* then we've to generate a new key/IV pair */
        sgx_read_rand((uint8_t *)&crypto_ctx.iv, sizeof(crypto_iv_t));
        sgx_read_rand((uint8_t *)&crypto_ctx.ekey, sizeof(crypto_ekey_t));
    } else {
        /* unseal our encryption key */
        enclave_crypto_ekey(_ekey, UCPRIV_DECRYPT);
    }

    memcpy(&iv, &crypto_ctx.iv, sizeof(crypto_iv_t));

    mbedtls_gcm_init(&gcm_ctx);
    mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, (uint8_t *)_ekey,
                       CRYPTO_AES_KEY_SIZE_BITS);
    mbedtls_gcm_starts(&gcm_ctx, (op == UCPRIV_ENCRYPT ? MBEDTLS_GCM_ENCRYPT
                                                       : MBEDTLS_GCM_DECRYPT),
                       (uint8_t *)&iv, sizeof(crypto_iv_t), NULL, 0);

    p_data = data;
    bytes_left = protolen;

    while (bytes_left > 0) {
        len = MIN(bytes_left, E_CRYPTO_BUFFER_LEN);

        memcpy(p_input, p_data, len);

        /* encrypt/decrypt */
        mbedtls_gcm_update(&gcm_ctx, len, p_input, p_output);

        memcpy(p_data, p_output, len);

        p_data += len;
        bytes_left -= len;
    }

    free(p_input);
    free(p_output);

    error = E_SUCCESS;

    if (op == UCPRIV_ENCRYPT) {
        mbedtls_gcm_finish(&gcm_ctx, (uint8_t *)&crypto_ctx.mac,
                           sizeof(crypto_tag_t));
        // seal the encryption key
        enclave_crypto_ekey(_ekey, UCPRIV_ENCRYPT);
        memcpy(p_ctx, &crypto_ctx, sizeof(crypto_context_t));
    } else {
        mbedtls_gcm_finish(&gcm_ctx, (uint8_t *)&gcm_mac, sizeof(crypto_tag_t));

        error = memcmp(&gcm_mac, &crypto_ctx.mac, sizeof(crypto_tag_t));
    }

    mbedtls_gcm_free(&gcm_ctx);
    return error;
}
