#include "crypto.h"

int
crypto_keywrap(uint8_t * keywrapping_key, uint8_t * sensitive_key)
{
    // TODO
    return -1;
}


int
crypto_keyunwrap(uint8_t * keywrapping_key, uint8_t * sensitive_key)
{
    // TODO
    return -1;
}

void
crypto_sha256(uint8_t * input,
              size_t    input_len,
              uint8_t   output[CRYPTO_HASH_BYTES])
{
    // TODO
}

int
crypto_encrypt(struct crypto_context * crypto_context,
               size_t                  input_len,
               uint8_t               * plaintext,
               uint8_t               * ciphertext,
               crypto_mac_t          * mac,
               uint8_t               * aad,
               size_t                  add_len)
{
    // TODO
    return -1;
}


int
crypto_decrypt(struct crypto_context * crypto_context,
               size_t                  input_len,
               uint8_t               * ciphertext,
               uint8_t               * plaintext,
               crypto_mac_t          * mac,
               uint8_t               * aad,
               size_t                  add_len)
{
    // TODO
    return -1;
}
