#pragma once

#include <stdlib.h>
#include <stdint.h>

#include <nexus_key.h>
#include <nexus_mac.h>

#include "crypto_context.h"

#define CRYPTO_BUFFER_SIZE 4096 // let's try 4KB

uint8_t *
crypto_aes_ecb_encrypt(struct nexus_key * key,
                       uint8_t          * in_buf,
                       size_t             data_size);


uint8_t *
crypto_aes_ecb_decrypt(struct nexus_key * key,
                       uint8_t          * in_buf,
                       size_t             data_size);



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
