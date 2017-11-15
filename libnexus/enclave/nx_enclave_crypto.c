#include "nx_trusted.h"

/**
 * Refactored function to apply key wrapping
 * TODO: add MAC'
 * @param key_encryption_key
 * @param sensitive_ekey
 * @param wrap whether to wrap or unwrap
 */
static int
_keywrapping_routine(uint8_t * key_encryption_key,
                     uint8_t * sensitive_ekey,
                     bool      wrap)
{
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);

    if (wrap) {
        mbedtls_aes_setkey_enc(
            &aes_context, key_encryption_key, CONFIG_EKEY_BITS);
    } else {
        mbedtls_aes_setkey_dec(
            &aes_context, key_encryption_key, CONFIG_EKEY_BITS);
    }

    mbedtls_aes_crypt_ecb(&aes_context,
                          (wrap ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
                          sensitive_ekey,
                          sensitive_ekey);

    mbedtls_aes_free(&aes_context);
    return 0;
}

static void
keywrap_crypto_context(struct crypto_context * crypto_context,
                       struct volumekey *      volumekey)
{
    _keywrapping_routine(
        volumekey->bytes, (uint8_t *)&crypto_context->ekey, true);
}

static void
unwrap_crypto_context(struct crypto_context * crypto_context,
                      struct volumekey *      volumekey)
{
    _keywrapping_routine(
        volumekey->bytes, (uint8_t *)&crypto_context->ekey, false);
}

/**
 * Refactored function to instantiate GCM encryption
 * @param gcm_context
 * @param gcm_mode (MBEDTLS_GCM_ENCRYPT/DECRYPT)
 * @param crypto_context
 */
static void
instantiate_gcm_context(mbedtls_gcm_context *   gcm_context,
                        struct crypto_context * crypto_context,
                        uint8_t *               iv,
                        uint8_t *               header,
                        size_t                  header_size,
                        int                     gcm_mode)
{
    mbedtls_gcm_setkey(gcm_context,
                       MBEDTLS_CIPHER_ID_AES,
                       (uint8_t *)&crypto_context->ekey,
                       CONFIG_EKEY_BITS);
    // add the header
    mbedtls_gcm_starts(
        gcm_context, gcm_mode, iv, CONFIG_IV_BYTES, header, header_size);
}

int
supernode_encryption1(struct supernode *  supernode,
                      struct volumekey *  volumekey,
                      struct supernode ** p_sealed_supernode)
{
    int                       ret                 = -1;
    size_t                    size                = 0;
    uint8_t                   iv[CONFIG_IV_BYTES] = { 0 };
    struct crypto_context *   crypto_context      = NULL;
    struct supernode_header * header              = NULL;
    struct supernode_header * sealed_header       = NULL;
    struct supernode *        sealed_supernode    = NULL;
    mbedtls_gcm_context       gcm_context;

    // copy the supernode into a new structure
    size             = supernode->header.total_size;
    sealed_supernode = (struct supernode *)calloc(1, size);
    if (sealed_supernode == NULL) {
        ocall_debug("allocation error");
        return -1;
    }

    header        = &supernode->header;
    sealed_header = &sealed_supernode->header;
    memcpy(sealed_header, header, sizeof(struct supernode_header));

    // initialize the crypto context
    crypto_context = &sealed_supernode->crypto_context;
    sgx_read_rand((uint8_t *)crypto_context, sizeof(struct crypto_context));
    memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);

    // perform the encryption
    mbedtls_gcm_init(&gcm_context);
    {
        instantiate_gcm_context(&gcm_context,
                                crypto_context,
                                iv,
                                (uint8_t *)sealed_header,
                                sizeof(struct supernode_header),
                                MBEDTLS_GCM_ENCRYPT);

        size = header->total_size - (sizeof(struct crypto_context)
                                     + sizeof(struct supernode_header));
        ret = mbedtls_gcm_update(&gcm_context,
                                 size,
                                 (uint8_t *)&supernode->user_table,
                                 (uint8_t *)&sealed_supernode->user_table);
        if (ret != 0) {
            ocall_debug("mbedtls_gcm_update() error on supernode");
            goto out;
        }

        mbedtls_gcm_finish(
            &gcm_context, (uint8_t *)&crypto_context->tag, CONFIG_TAG_BYTES);
    }

    // wrap the crypto context and send it out.
    keywrap_crypto_context(crypto_context, volumekey);

    *p_sealed_supernode = sealed_supernode;

    ret = 0;
out:
    if (ret) {
        my_free(sealed_supernode);
    }

    mbedtls_gcm_free(&gcm_context);

    return ret;
}

int
supernode_decryption1(struct supernode *  sealed_supernode,
                      struct volumekey *  volumekey,
                      struct supernode ** p_supernode)
{
    int                       ret                   = -1;
    size_t                    size                  = 0;
    uint8_t                   iv[CONFIG_IV_BYTES]   = { 0 };
    uint8_t                   tag[CONFIG_TAG_BYTES] = { 0 };
    struct crypto_context *   crypto_context        = NULL;
    struct supernode_header * header                = NULL;
    struct supernode_header * sealed_header         = NULL;
    struct supernode *        supernode             = NULL;
    mbedtls_gcm_context       gcm_context;

    size      = sealed_supernode->header.total_size;
    supernode = (struct supernode *)calloc(1, size);
    if (supernode == NULL) {
        ocall_debug("allocation error");
        return -1;
    }

    header        = &supernode->header;
    sealed_header = &sealed_supernode->header;
    memcpy(header, sealed_header, sizeof(struct supernode_header));
    memcpy(&supernode->crypto_context,
           &sealed_supernode->crypto_context,
           sizeof(struct crypto_context));

    // unwrap the crypto context and start decrypting
    crypto_context = &supernode->crypto_context;
    unwrap_crypto_context(crypto_context, volumekey);
    memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);

    mbedtls_gcm_init(&gcm_context);
    {
        instantiate_gcm_context(&gcm_context,
                                crypto_context,
                                iv,
                                (uint8_t *)header,
                                sizeof(struct supernode_header),
                                MBEDTLS_GCM_DECRYPT);

        size = sealed_header->total_size - (sizeof(struct crypto_context)
                                            + sizeof(struct supernode_header));
        ret = mbedtls_gcm_update(&gcm_context,
                                 size,
                                 (uint8_t *)&sealed_supernode->user_table,
                                 (uint8_t *)&supernode->user_table);
        if (ret != 0) {
            ocall_debug("mbedtls_gcm_update() error on supernode");
            goto out;
        }

        mbedtls_gcm_finish(&gcm_context, (uint8_t *)&tag, CONFIG_TAG_BYTES);
    }

    ret = memcmp(&tag, &sealed_supernode->crypto_context.tag, CONFIG_TAG_BYTES);
    if (ret != 0) {
        ocall_debug("integrity check failed");
        goto out;
    }

    *p_supernode = supernode;

    ret = 0;
out:
    if (ret) {
        my_free(supernode);
    }

    mbedtls_gcm_free(&gcm_context);

    return ret;
}

// TODO
int
dirnode_encryption1(struct dirnode *   dirnode,
                    struct volumekey * volkey,
                    struct dirnode **  p_sealed_dirnode)
{
    *p_sealed_dirnode = dirnode_copy(dirnode);
    return (*p_sealed_dirnode == NULL) ? -1 : 0;
}

int
dirnode_encryption(struct dirnode * dirnode, struct dirnode ** p_sealed_dirnode)
{
    struct volumekey * volumekey = NULL;

    volumekey = volumekey_from_rootuuid(&dirnode->header.root_uuid);
    if (volumekey == NULL) {
        ocall_debug("could not find dirnode volumekey");
        return -1;
    }

    return dirnode_encryption1(dirnode, volumekey, p_sealed_dirnode);
}

// TODO
int
dirnode_decryption(struct dirnode * sealed_dirnode, struct dirnode ** p_dirnode)
{
    *p_dirnode = dirnode_copy(sealed_dirnode);
    return (*p_dirnode == NULL) ? -1 : 0;
}

// TODO
int
volumekey_wrap(struct volumekey * volkey)
{
    return _keywrapping_routine(
        (uint8_t *)&enclave_sealing_key, volkey->bytes, true);
}

int
volumekey_unwrap(struct volumekey * volkey)
{
    return _keywrapping_routine(
        (uint8_t *)&enclave_sealing_key, volkey->bytes, false);
}
