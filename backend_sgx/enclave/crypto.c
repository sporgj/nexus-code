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
crypto_keywrap(struct nexus_key * keywrapping_key, struct nexus_key * sensitive_key)
{
    return __keywrap(keywrapping_key->bytes, sensitive_key->bytes, true);
}


int
crypto_keyunwrap(struct nexus_key * keywrapping_key, struct nexus_key * sensitive_key)
{
    return __keywrap(keywrapping_key->bytes, sensitive_key->bytes, false);
}

int
crypto_encrypt(struct nexus_crypto_ctx * crypto_context,
               size_t                    input_len,
               uint8_t                 * plaintext,
               uint8_t                 * ciphertext,
               struct nexus_mac        * mac,
               uint8_t                 * aad,
               size_t                    add_len)
{
    struct nexus_key * iv_copy = NULL;

    int ret = -1;


    // generate key and IV
    nexus_generate_key(&crypto_context->key, NEXUS_RAW_128_KEY);
    nexus_generate_key(&crypto_context->iv, NEXUS_RAW_128_KEY);

    iv_copy = nexus_clone_key(&crypto_context->iv);


    // intiialize the gcm context and perform the encryption
    {
        mbedtls_gcm_context gcm_context;

        mbedtls_gcm_init(&gcm_context);

        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->key->key,
                           nexus_key_size_bits(&crypto_context->key));

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_ENCRYPT,
                           iv_copy->key,
                           nexus_key_size_bytes(iv_copy),
                           (uint8_t *) aad, // AAD used for integrity
                           aad_len);


        ret = mbedtls_gcm_update(&gcm_context, input_len, plaintext, ciphertext);
        if (ret) {
            mbedtls_gcm_free(&gcm_context);
            goto out;
        }


        mbedtls_gcm_finish(&gcm_context,
                           (uint8_t *)&crypto_context->mac,
                           sizeof(struct nexus_mac));

        mbedtls_gcm_free(&gcm_context);
    }

    // if the mac is needed
    if (mac) {
        nexus_mac_copy(&crypto_context->mac, mac);
    }

    ret = 0;
out:
    if (iv_copy) {
        nexus_free_key(iv_copy);
    }

    return ret;
}


int
crypto_decrypt(struct nexus_crypto_ctx * crypto_context,
               size_t                    input_len,
               uint8_t                 * ciphertext,
               uint8_t                 * plaintext,
               struct nexus_mac        * mac,
               uint8_t                 * aad,
               size_t                    add_len)
{
    struct nexus_key * iv_copy = NULL;

    struct nexus_mac computed_mac;

    int ret = -1;

    iv_copy = nexus_clone_key(&crypto_context->iv);


    // intiialize the gcm context and perform the encryption
    {
        mbedtls_gcm_context gcm_context;

        mbedtls_gcm_init(&gcm_context);

        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey->key,
                           neuxs_key_size_bits(&crypto_context->ekey));

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_DECRYPT,
                           iv_copy->key,
                           nexus_key_size_bytes(iv_copy),
                           (uint8_t *) aad, // AAD used for integrity
                           aad_len);


        ret = mbedtls_gcm_update(&gcm_context, input_len, plaintext, ciphertext);
        if (ret) {
            mbedtls_gcm_free(&gcm_context);
            goto out;
        }

        mbedtls_gcm_finish(&gcm_context,
                           (uint8_t *)&computed_mac,
                           sizeof(struct nexus_mac));

        mbedtls_gcm_free(&gcm_context);
    }

    ret = memcmp(&computed_mac, &crypto_context->mac, sizeof(struct nexus_mac));

    if (ret == 0 && mac) {
        memcpy(mac, &crypto_context->mac, sizeof(struct nexus_mac));
    }

    ret = 0;
out:
    return ret;
}
