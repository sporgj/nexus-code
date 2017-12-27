#pragma once

#include <stdlib.h>
#include <stdint.h>

#define CRYPTO_HASH_BYTES  32  // sha256

#define CRYPTO_NONCE_BYTES 64


// things to fit in the crypto context

#define CRYPTO_EKEY_BYTES   16
#define CRYPTO_EKEY_BITS   (CONFIG_EKEY_BYTES << 3)
#define CRYPTO_IV_BYTES     16
#define CRYPTO_MAC_BYTES    16 // size of the GCM integrity tag


typedef struct {
    uint8_t bytes[CRYPTO_EKEY_BYTES];
} crypto_ekey_t;

typedef struct {
    uint8_t bytes[CRYPTO_IV_BYTES];
} crypto_iv_t;

typedef struct {
    uint8_t bytes[CRYPTO_MAC_BYTES];
} crypto_mac_t;


struct crypto_context {
    crypto_ekey_t ekey;
    crypto_iv_t   iv;
    crypto_mac_t  mac;
} __attribute__((packed));


// deterministic encryption of a sensitive key using the keywrapping key
int
crypto_keywrap(uint8_t * keywrapping_key, uint8_t * sensitive_key);


// deterministic decryption of a sensitive key using the keywrapping key
int
crypto_keyunwrap(uint8_t * keywrapping_key, uint8_t * sensitive_key);



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
