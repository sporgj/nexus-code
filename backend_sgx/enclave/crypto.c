#include "enclave_internal.h"

#include <stdbool.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>


int
__crypto_aes_ecb_encrypt(struct nexus_key * key,
                         size_t             data_size,
                         uint8_t          * in_buf,
                         uint8_t          * out_buf)
{
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);

    int bit_length = 0;

    if (key->type == NEXUS_RAW_128_KEY) {
        bit_length = 128;
    } else if (key->type == NEXUS_RAW_256_KEY) {
        bit_length = 256;
    } else {
        log_error("invalid key type (%s) for AES ECB\n", nexus_key_type_to_str(key->type));
        return -1;
    }

    mbedtls_aes_setkey_enc(&aes_context, key->key, bit_length);

    {
        size_t i  = 0;

        while (i < data_size) {
            mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_ENCRYPT, in_buf + i, out_buf + i);
            i += 16;
        }
    }

    mbedtls_aes_free(&aes_context);

    return 0;
}

uint8_t *
crypto_aes_ecb_encrypt(struct nexus_key * key,
                       uint8_t          * in_buf,
                       size_t             data_size)
{
    uint8_t * out_buf = NULL;

    int ret = 0;

    out_buf = nexus_malloc(data_size);

    ret = __crypto_aes_ecb_encrypt(key, data_size, in_buf, out_buf);

    if (ret == -1) {
        log_error("Could not encrypt buffer\n");
        nexus_free(out_buf);
        return NULL;
    }

    return out_buf;
}


int
__crypto_aes_ecb_decrypt(struct nexus_key * key,
                         size_t             data_size,
                         uint8_t          * in_buf,
                         uint8_t          * out_buf)
{
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);

    int bit_length = 0;

    if (key->type == NEXUS_RAW_128_KEY) {
        bit_length = 128;
    } else if (key->type == NEXUS_RAW_256_KEY) {
        bit_length = 256;
    } else {
        log_error("invalid key type (%s) for AES ECB\n", nexus_key_type_to_str(key->type));
        return -1;
    }

    mbedtls_aes_setkey_dec(&aes_context, key->key, bit_length);

    {
        size_t i  = 0;

        while (i < data_size) {
            mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_DECRYPT, in_buf + i, out_buf + i);
            i += 16;
        }
    }

    mbedtls_aes_free(&aes_context);

    return 0;
}

uint8_t *
crypto_aes_ecb_decrypt(struct nexus_key * key,
                       uint8_t          * in_buf,
                       size_t             data_size)
{
    uint8_t * out_buf = NULL;

    int ret = 0;

    out_buf = nexus_malloc(data_size);

    ret = __crypto_aes_ecb_decrypt(key, data_size, in_buf, out_buf);

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
