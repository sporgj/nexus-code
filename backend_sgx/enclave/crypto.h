#pragma once

#include <stdlib.h>
#include <stdint.h>

#include <nexus_key.h>
#include <nexus_mac.h>


struct nexus_crypto_ctx {
    struct nexus_key key;
    struct nexus_key iv;   /* Isn't this basically just like a key? Or do we need a separate 'struct nexus_iv'*/
    struct nexus_mac mac;
} __attribute__((packed));












// deterministic encryption of a sensitive key using the keywrapping key
int
crypto_keywrap(crypto_ekey_t * keywrapping_key, crypto_ekey_t * sensitive_key);


// deterministic decryption of a sensitive key using the keywrapping key
int
crypto_keyunwrap(crypto_ekey_t * keywrapping_key, crypto_ekey_t * sensitive_key);



// computes the sha256
void
crypto_sha256(uint8_t * input,
              size_t    input_len,
              uint8_t   output[CRYPTO_HASH_BYTES]);


/**
 * Encrypts and seals buffer using the specified crypto_context 
 * @param crypto_context will be overriden with new key/iv/mac
 * @param input_len
 * @param plaintext
 * @param ciphertext
 * @param mac [optional] the resulting mac of plaintext + aad
 * @param aad [optional] additional authentication data for integrity
 * @param aad_len
 *
 * @return 0 on success. Overwriting crypto_context
 */
int
crypto_encrypt(struct crypto_context * crypto_context,
               size_t                  input_len,
               uint8_t               * plaintext,
               uint8_t               * ciphertext,
               crypto_mac_t          * mac,
               uint8_t               * aad,
               size_t                  add_len);


/**
 * Encrypts and seals buffer using the specified crypto_context 
 * @param crypto_context 
 * @param input_len
 * @param ciphertext
 * @param plaintext
 * @param mac [optional] the mac of the plaintext + aad
 * @param aad [optional] additional authentication data for integrity
 * @param aad_len
 *
 * @return 0 on success. Overwriting crypto_context
 */
int
crypto_decrypt(struct crypto_context * crypto_context,
               size_t                  input_len,
               uint8_t               * ciphertext,
               uint8_t               * plaintext,
               crypto_mac_t          * mac,
               uint8_t               * aad,
               size_t                  add_len);
