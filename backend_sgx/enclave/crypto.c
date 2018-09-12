#include "enclave_internal.h"

#include <stdbool.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>


int
__crypto_aes_ecb_encrypt(struct nexus_key * key,
                         uint8_t          * in_buf,
                         uint8_t          * out_buf,
                         size_t             block_count)
{
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);

    mbedtls_aes_setkey_enc(&aes_context, key->key, nexus_key_bits(key));

    for (size_t i = 0; i < block_count * AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
        mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_ENCRYPT, in_buf + i, out_buf + i);
    }

    mbedtls_aes_free(&aes_context);

    return 0;
}

uint8_t *
crypto_aes_encrypt_key(struct nexus_key * key_encryption_key, struct nexus_key * secret_key)
{
    uint8_t * out_buf = NULL;

    int ret = 0;

    switch (secret_key->type) {
    case NEXUS_RAW_128_KEY:
        out_buf = nexus_malloc(16);
        ret     = __crypto_aes_ecb_encrypt(key_encryption_key, secret_key->key, out_buf, 1);
        break;
    case NEXUS_RAW_256_KEY:
        out_buf = nexus_malloc(32);
        ret     = __crypto_aes_ecb_encrypt(key_encryption_key, secret_key->key, out_buf, 2);
        break;
    default:
        log_error("incorrect secret_key type\n");
        return NULL;
    }

    if (ret == -1) {
        log_error("Could not encrypt buffer\n");
        nexus_free(out_buf);
        return NULL;
    }

    return out_buf;
}


int
__crypto_aes_ecb_decrypt(struct nexus_key * key,
                         uint8_t          * in_buf,
                         uint8_t          * out_buf,
                         size_t             block_count)
{
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);

    mbedtls_aes_setkey_dec(&aes_context, key->key, nexus_key_bits(key));

    for (size_t i = 0; i < block_count * AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
        mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_DECRYPT, in_buf + i, out_buf + i);
    }

    mbedtls_aes_free(&aes_context);

    return 0;
}

uint8_t *
crypto_aes_decrypt_key(struct nexus_key * key_encryption_key, struct nexus_key * secret_key)
{
    uint8_t * out_buf = NULL;

    int ret = 0;

    switch (secret_key->type) {
    case NEXUS_WRAPPED_128_KEY:
        out_buf = nexus_malloc(16);
        ret     = __crypto_aes_ecb_decrypt(key_encryption_key, secret_key->key, out_buf, 1);
        break;
    case NEXUS_WRAPPED_256_KEY:
        out_buf = nexus_malloc(32);
        ret     = __crypto_aes_ecb_decrypt(key_encryption_key, secret_key->key, out_buf, 2);
        break;
    default:
        log_error("incorrect secret_key type\n");
        return NULL;
    }

    if (ret == -1) {
        log_error("Could not decrypt buffer\n");
        nexus_free(out_buf);
        return NULL;
    }

    return out_buf;
}


int
crypto_gcm_encrypt(struct nexus_crypto_ctx * crypto_context,
                   size_t                    input_len,
                   uint8_t                 * plaintext,
                   uint8_t                 * ciphertext,
                   struct nexus_mac        * mac,
                   uint8_t                 * aad,
                   size_t                    aad_len)
{
    struct nexus_key * iv_copy = NULL;

    mbedtls_gcm_context gcm_context;

    uint8_t input_buffer[CRYPTO_BUFFER_SIZE]  = { 0 }; // XXX: is zeroing really necessary?
    uint8_t output_buffer[CRYPTO_BUFFER_SIZE] = { 0 };

    int bytes_left = 0;
    int size       = 0;

    int ret = -1;


    iv_copy = nexus_clone_key(&(crypto_context->iv));


    // intiialize the gcm context and perform the encryption
    mbedtls_gcm_init(&gcm_context);

    mbedtls_gcm_setkey(&gcm_context,
                       MBEDTLS_CIPHER_ID_AES,
                       crypto_context->key.key,
                       nexus_key_bits(&(crypto_context->key)));

    mbedtls_gcm_starts(&gcm_context,
                       MBEDTLS_GCM_ENCRYPT,
                       iv_copy->key,
                       nexus_key_bytes(iv_copy),
                       (uint8_t *) aad, // AAD used for integrity
                       aad_len);


    bytes_left = input_len;

    while (bytes_left > 0) {
        size = min(bytes_left, CRYPTO_BUFFER_SIZE);

        memcpy(input_buffer, plaintext, size);

        ret = mbedtls_gcm_update(&gcm_context, size, input_buffer, output_buffer);
        if (ret != 0) {
            log_error("mbedtls_gcm_update() FAILED\n");
            goto out;
        }

        memcpy(ciphertext, output_buffer, size);

        bytes_left -= size;

        plaintext  += size;
        ciphertext += size;
    }

    mbedtls_gcm_finish(&gcm_context, (uint8_t *)&(crypto_context->mac), sizeof(struct nexus_mac));

    // if the mac is needed
    if (mac != NULL) {
        nexus_mac_copy(&(crypto_context->mac), mac);
    }

    ret = 0;
out:
    mbedtls_gcm_free(&gcm_context);

    if (iv_copy) {
        nexus_free_key(iv_copy);
        nexus_free(iv_copy);
    }

    return ret;
}


int
crypto_gcm_decrypt(struct nexus_crypto_ctx * crypto_context,
                   size_t                    input_len,
                   uint8_t                 * ciphertext,
                   uint8_t                 * plaintext,
                   struct nexus_mac        * mac,
                   uint8_t                 * aad,
                   size_t                    aad_len)
{
    struct nexus_key * iv_copy = NULL;

    mbedtls_gcm_context gcm_context;

    uint8_t input_buffer[CRYPTO_BUFFER_SIZE]  = { 0 }; // XXX: is zeroing really necessary?
    uint8_t output_buffer[CRYPTO_BUFFER_SIZE] = { 0 };

    struct nexus_mac computed_mac;

    int bytes_left = 0;
    int size       = 0;

    int ret = -1;


    iv_copy = nexus_clone_key(&(crypto_context->iv));

    // intiialize the gcm context and perform the encryption
    mbedtls_gcm_init(&gcm_context);

    mbedtls_gcm_setkey(&gcm_context,
                       MBEDTLS_CIPHER_ID_AES,
                       crypto_context->key.key,
                       nexus_key_bits(&(crypto_context->key)));

    mbedtls_gcm_starts(&gcm_context,
                       MBEDTLS_GCM_DECRYPT,
                       iv_copy->key,
                       nexus_key_bytes(iv_copy),
                       (uint8_t *) aad, // AAD used for integrity
                       aad_len);

    bytes_left = input_len;

    while (bytes_left > 0) {
        size = min(bytes_left, CRYPTO_BUFFER_SIZE);

        memcpy(input_buffer, ciphertext, size);


        ret = mbedtls_gcm_update(&gcm_context, size, input_buffer, output_buffer);
        if (ret != 0) {
            log_error("mbedtls_gcm_update FAILED\n");
            goto out;
        }

        memcpy(plaintext, output_buffer, size);

        bytes_left -= size;

        plaintext  += size;
        ciphertext += size;
    }

    mbedtls_gcm_finish(&gcm_context, (uint8_t *)&computed_mac, sizeof(struct nexus_mac));

    if (nexus_mac_compare(&computed_mac, &(crypto_context->mac)) != 0) {
        log_error("nexus_mac_compare() FAILED\n");
        ret = -1;
        goto out;
    }

    if (mac != NULL) {
        nexus_mac_copy(&computed_mac, mac);
    }

    ret = 0;
out:
    mbedtls_gcm_free(&gcm_context);

    if (iv_copy) {
        nexus_free_key(iv_copy);
        nexus_free(iv_copy);
    }

    return ret;
}


uint8_t *
crypto_ecdh_encrypt(struct ecdh_public_key  * pk,
                    struct ecdh_secret_key  * sk,
                    uint8_t            * data,
                    size_t               in_len,
                    int                * out_len,
                    struct ecdh_nonce       * nonce)
{
    int total_len        = crypto_box_ZEROBYTES + in_len;

    uint8_t * plaintext  = nexus_malloc(total_len);

    uint8_t * ciphertext = nexus_malloc(total_len);


    memcpy(plaintext + crypto_box_ZEROBYTES, data, in_len);

    // performs some salsal operation
    if (crypto_box(ciphertext, plaintext, total_len, (uint8_t *)nonce, pk->bytes, sk->bytes)) {
        log_error("crypto_box FAILED\n");
        goto err;
    }

    nexus_free(plaintext);

    *out_len = total_len;

    return ciphertext;

err:
    nexus_free(plaintext);
    nexus_free(ciphertext);

    return NULL;
}

uint8_t *
crypto_ecdh_decrypt(struct ecdh_public_key  * pk,
                    struct ecdh_secret_key  * sk,
                    uint8_t            * data,
                    size_t               total_len,
                    int                * plain_len,
                    int                * offset,
                    struct ecdh_nonce       * nonce)
{
    uint8_t * plaintext  = nexus_malloc(total_len);

    uint8_t * ciphertext = nexus_malloc(total_len);


    memcpy(ciphertext, data, total_len);

    // runs the salsa stream cipher
    if (crypto_box_open(plaintext, ciphertext, total_len, (uint8_t *)nonce, pk->bytes, sk->bytes)) {
        log_error("crypto_box_open FAILED\n");
        goto err;
    }

    nexus_free(ciphertext);

    *plain_len = total_len - crypto_box_ZEROBYTES;
    *offset = crypto_box_ZEROBYTES;

    return plaintext;

err:
    nexus_free(plaintext);
    nexus_free(ciphertext);

    return NULL;
}


uint8_t *
crypto_seal_data(uint8_t * data, size_t size, size_t * p_sealed_len)
{
    size_t              sealed_len  = sgx_calc_sealed_data_size(0, size);

    sgx_sealed_data_t * sealed_data = nexus_malloc(sealed_len);

    {
        int ret = sgx_seal_data(0, NULL, size, data, sealed_len, sealed_data);

        if (ret != 0) {
            nexus_free(sealed_data);
            log_error("sgx_seal_data() FAILED (ret=%x)\n", ret);
            return NULL;
        }
    }

    *p_sealed_len = sealed_len;

    return (uint8_t *)sealed_data;
}


uint8_t *
crypto_unseal_data(uint8_t * data, size_t size, size_t * p_unsealed_len)
{
    sgx_sealed_data_t * sealed_data   = (sgx_sealed_data_t *)data;

    uint32_t            unsealed_len  = sgx_get_encrypt_txt_len(sealed_data);

    uint8_t           * unsealed_data = nexus_malloc(unsealed_len);

    {
        int ret = sgx_unseal_data(sealed_data, NULL, 0, unsealed_data, &unsealed_len);

        if (ret != 0) {
            nexus_free(unsealed_data);
            log_error("sgx_unseal_data FAILED (ret=%x)\n", ret);
            return NULL;
        }
    }

    *p_unsealed_len = unsealed_len;

    return (uint8_t *)unsealed_data;
}
