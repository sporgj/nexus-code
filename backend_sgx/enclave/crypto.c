#include "crypto.h"

#include <stdbool.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>


static int
__keywrap(uint8_t * key_encryption_key, uint8_t * sensitive_ekey, bool wrap)
{
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);

    if (wrap) {
        mbedtls_aes_setkey_enc(
            &aes_context, key_encryption_key, CRYPTO_EKEY_BITS);
    } else {
        mbedtls_aes_setkey_dec(
            &aes_context, key_encryption_key, CRYPTO_EKEY_BITS);
    }

    mbedtls_aes_crypt_ecb(&aes_context,
                          (wrap ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
                          sensitive_ekey,
                          sensitive_ekey);

    mbedtls_aes_free(&aes_context);


    return 0;
}

int
crypto_keywrap(crypto_ekey_t * keywrapping_key, crypto_ekey_t * sensitive_key)
{
    return __keywrap(keywrapping_key->bytes, sensitive_key->bytes, true);
}


int
crypto_keyunwrap(crypto_ekey_t * keywrapping_key, crypto_ekey_t * sensitive_key)
{
    return __keywrap(keywrapping_key->bytes, sensitive_key->bytes, false);
}

void
crypto_sha256(uint8_t * input,
              size_t    input_len,
              uint8_t   output[CRYPTO_HASH_BYTES])
{
    mbedtls_sha256(input, input_len, output, 0); // 0 -> sha256, 1 -> sha224
}

int
crypto_encrypt(struct crypto_context * crypto_context,
               size_t                  input_len,
               uint8_t               * plaintext,
               uint8_t               * ciphertext,
               crypto_mac_t          * mac,
               uint8_t               * aad,
               size_t                  aad_len)
{
    crypto_iv_t iv_copy;

    int ret = -1;


    // generate key and IV
    sgx_read_rand((uint8_t *)crypto_context, sizeof(struct crypto_context));

    memcpy(&iv_copy, &crypto_context->iv, sizeof(crypto_iv_t));


    // intiialize the gcm context and perform the encryption
    {
        mbedtls_gcm_context gcm_context;

        mbedtls_gcm_init(&gcm_context);

        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey,
                           CRYPTO_EKEY_BITS);

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_ENCRYPT,
                           iv_copy.bytes,
                           CRYPTO_IV_BYTES,
                           (uint8_t *) aad, // AAD used for integrity
                           aad_len);


        ret = mbedtls_gcm_update(&gcm_context, input_len, plaintext, ciphertext);
        if (ret) {
            mbedtls_gcm_free(&gcm_context);
            goto out;
        }


        mbedtls_gcm_finish(&gcm_context,
                           (uint8_t *)&crypto_context->mac,
                           CRYPTO_MAC_BYTES);

        mbedtls_gcm_free(&gcm_context);
    }

    // if the mac is needed
    if (mac) {
        memcpy(mac, &crypto_context->mac, sizeof(crypto_mac_t));
    }

    ret = 0;
out:
    return ret;
}


int
crypto_decrypt(struct crypto_context * crypto_context,
               size_t                  input_len,
               uint8_t               * ciphertext,
               uint8_t               * plaintext,
               crypto_mac_t          * mac,
               uint8_t               * aad,
               size_t                  aad_len)
{
    crypto_iv_t  iv_copy;
    crypto_mac_t computed_mac;

    int ret = -1;


    memcpy(&iv_copy, &crypto_context->iv, sizeof(crypto_iv_t));


    // intiialize the gcm context and perform the encryption
    {
        mbedtls_gcm_context gcm_context;

        mbedtls_gcm_init(&gcm_context);

        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey,
                           CRYPTO_EKEY_BITS);

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_DECRYPT,
                           iv_copy.bytes,
                           CRYPTO_IV_BYTES,
                           (uint8_t *) aad, // AAD used for integrity
                           aad_len);


        ret = mbedtls_gcm_update(&gcm_context, input_len, plaintext, ciphertext);
        if (ret) {
            mbedtls_gcm_free(&gcm_context);
            goto out;
        }

        mbedtls_gcm_finish(&gcm_context,
                           (uint8_t *)&computed_mac,
                           CRYPTO_MAC_BYTES);

        mbedtls_gcm_free(&gcm_context);
    }

    ret = memcmp(&computed_mac, &crypto_context->mac, sizeof(crypto_mac_t));

    if (ret == 0 && mac) {
        memcpy(mac, &crypto_context->mac, sizeof(crypto_mac_t));
    }

    ret = 0;
out:
    return ret;
}
