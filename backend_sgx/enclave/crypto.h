#pragma once

#include <stdlib.h>
#include <stdint.h>

#include <nexus_key.h>
#include <nexus_mac.h>

#include "crypto_context.h"

// ---- GCM stuff ----
#define GCM128_KEY_SIZE (16)
#define GCM128_IV_SIZE  (16)

#define AES_BLOCK_SIZE  (16)

#define GCM128_TAG_SIZE (16)


struct ecdh_public_key;
struct ecdh_secret_key;
struct ecdh_nonce;


#define CRYPTO_BUFFER_SIZE 4096 // let's try 4KB


uint8_t *
crypto_aes_encrypt_key(struct nexus_key * key_encryption_key, struct nexus_key * secret_key);

uint8_t *
crypto_aes_decrypt_key(struct nexus_key * key_encryption_key, struct nexus_key * secret_key);



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
crypto_gcm_encrypt(struct nexus_crypto_ctx * crypto_context,
                   size_t                    input_len,
                   uint8_t                 * plaintext,
                   uint8_t                 * ciphertext,
                   struct nexus_mac        * mac,
                   uint8_t                 * aad,
                   size_t                    add_len);


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
crypto_gcm_decrypt(struct nexus_crypto_ctx * crypto_context,
                   size_t                    input_len,
                   uint8_t                 * ciphertext,
                   uint8_t                 * plaintext,
                   struct nexus_mac        * mac,
                   uint8_t                 * aad,
                   size_t                    add_len);


uint8_t *
crypto_ecdh_encrypt(struct ecdh_public_key  * pk,
                    struct ecdh_secret_key  * sk,
                    uint8_t            * data,
                    size_t               in_len,
                    int                * out_len,
                    struct ecdh_nonce       * nonce);

/**
 * Uses tweetnacl crypto_box api to generate common secret from ECDH keypair
 */
uint8_t *
crypto_ecdh_decrypt(struct ecdh_public_key  * pk,
                    struct ecdh_secret_key  * sk,
                    uint8_t            * data,
                    size_t               total_len,
                    int                * plain_len,
                    int                * offset,
                    struct ecdh_nonce       * nonce);


uint8_t *
crypto_seal_data(uint8_t * data, size_t size, size_t * p_sealed_len);

uint8_t *
crypto_unseal_data(uint8_t * data, size_t size, size_t * p_unsealed_len);
