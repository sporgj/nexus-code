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

    sealed_header->version += 1;

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

static int
_encrypt_dirnode_direntries(struct dirnode_wrapper * dirnode_wrapper,
                            struct dirnode *         sealed_dirnode,
                            mbedtls_gcm_context *    gcm_context)
{
    int                            ret           = -1;
    size_t                         size          = 0;
    uint8_t *                      sealed_buffer = NULL;
    struct dirnode *               dirnode       = dirnode_wrapper->dirnode;
    struct dirnode_direntry_list * head      = &dirnode_wrapper->direntry_head;
    struct dirnode_direntry_item * entryitem = NULL;
    struct dirnode_direntry *      direntry  = NULL;

    sealed_buffer = (uint8_t *)&sealed_dirnode->entries;

    // iterate direntries and encrypt
    TAILQ_FOREACH(entryitem, head, next_item)
    {
        direntry = entryitem->direntry;
        size     = direntry->entry_len;

        ret = mbedtls_gcm_update(
            gcm_context, size, (uint8_t *)direntry, sealed_buffer);

        if (ret != 0) {
            ocall_debug("mbedtls_gcm_update() error on dirnode");
            goto out;
        }

        sealed_buffer += size;
    }

    ret = 0;
out:
    return ret;
}

static struct dirnode *
_instantiate_dirnode_crypto(struct dirnode *        dirnode,
                            mbedtls_gcm_context *   gcm_context,
                            uint8_t * iv)
{
    int                     ret                 = -1;
    struct crypto_context * crypto_context      = NULL;
    struct dirnode_header * header              = NULL;
    struct dirnode_header * sealed_header       = NULL;
    struct dirnode *        sealed_dirnode      = NULL;

    // create the dirnode and instantiate its crypto context
    header         = &dirnode->header;

    sealed_dirnode = (struct dirnode *)calloc(1, header->total_size);
    if (sealed_dirnode == NULL) {
        ocall_print("allocation error");
        return NULL;
    }

    // increment the version of header
    header->version += 1;

    sealed_header = &sealed_dirnode->header;
    memcpy(sealed_header, header, sizeof(struct dirnode_header));

    crypto_context = &sealed_dirnode->crypto_context;
    sgx_read_rand((uint8_t *)crypto_context, sizeof(struct crypto_context));
    memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);

    mbedtls_gcm_init(gcm_context);
    instantiate_gcm_context(gcm_context,
            crypto_context,
            iv,
            (uint8_t *)sealed_header,
            sizeof(struct dirnode_header),
            MBEDTLS_GCM_ENCRYPT);

    return sealed_dirnode;
}

int
dirnode_encryption1(struct dirnode_wrapper * dirnode_wrapper,
                    struct dirnode *         dirnode,
                    struct volumekey *       volumekey,
                    struct dirnode **        p_sealed_dirnode)
{
    int                     ret                 = -1;
    uint8_t                 iv[CONFIG_IV_BYTES] = { 0 };
    struct crypto_context * crypto_context      = NULL;
    struct dirnode *        sealed_dirnode      = NULL;
    mbedtls_gcm_context     gcm_context;

    sealed_dirnode = _instantiate_dirnode_crypto(dirnode, &gcm_context, iv);
    if (sealed_dirnode == NULL) {
        ocall_print("_instantiate_dirnode_crypto FAILED");
        return -1;
    }

    if (dirnode_wrapper != NULL && sealed_dirnode->header.dir_size > 0) {
        ret = _encrypt_dirnode_direntries(
            dirnode_wrapper, sealed_dirnode, &gcm_context);
        if (ret != 0) {
            ocall_debug("_encrypt_dirnode_direntries() FAILED");
            goto out;
        }
    }

    // wrap the crypto context and send it out.
    crypto_context = &sealed_dirnode->crypto_context;
    mbedtls_gcm_finish(
        &gcm_context, (uint8_t *)&crypto_context->tag, CONFIG_TAG_BYTES);

    keywrap_crypto_context(crypto_context, volumekey);

    *p_sealed_dirnode = sealed_dirnode;

    ret = 0;
out:
    if (ret != 0) {
        my_free(sealed_dirnode);
    }

    mbedtls_gcm_free(&gcm_context);

    return ret;
}

int
dirnode_encryption(struct dirnode_wrapper * dirnode_wrapper,
                   struct dirnode **        p_sealed_dirnode)
{
    struct dirnode *   dirnode   = dirnode_wrapper->dirnode;
    struct volumekey * volumekey = dirnode_wrapper->volumekey;

    return dirnode_encryption1(dirnode_wrapper, dirnode, volumekey, p_sealed_dirnode);
}

int
dirnode_decryption(struct dirnode *   sealed_dirnode,
                   struct volumekey * volumekey,
                   struct dirnode **  p_dirnode)
{
    int                       ret                   = -1;
    size_t                    size                  = 0;
    uint8_t                   iv[CONFIG_IV_BYTES]   = { 0 };
    uint8_t                   tag[CONFIG_TAG_BYTES] = { 0 };
    struct crypto_context *   crypto_context        = NULL;
    struct dirnode_header *   header                = NULL;
    struct dirnode_header *   sealed_header         = NULL;
    struct dirnode *          dirnode               = NULL;
    mbedtls_gcm_context       gcm_context;

    // allocate the necessary memory and start copying header information
    sealed_header = &sealed_dirnode->header;
    size          = sealed_header->total_size;

    dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    if (dirnode == NULL) {
        ocall_print("allocation error");
        return -1;
    }

    header = &dirnode->header;
    memcpy(header, sealed_header, sizeof(struct dirnode_header));
    memcpy(&dirnode->crypto_context,
           &sealed_dirnode->crypto_context,
           sizeof(struct crypto_context));

    crypto_context = &dirnode->crypto_context;
    unwrap_crypto_context(crypto_context, volumekey);
    memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);

    mbedtls_gcm_init(&gcm_context);
    instantiate_gcm_context(&gcm_context,
            crypto_context,
            iv,
            (uint8_t *)header,
            sizeof(struct dirnode_header),
            MBEDTLS_GCM_DECRYPT);

    size = sealed_dirnode->header.dir_size;
    mbedtls_gcm_update(&gcm_context,
                       size,
                       (uint8_t *)&sealed_dirnode->entries,
                       (uint8_t *)&dirnode->entries);

    mbedtls_gcm_finish(&gcm_context, (uint8_t *)&tag, CONFIG_TAG_BYTES);

    ret = memcmp(&tag, &sealed_dirnode->crypto_context.tag, CONFIG_TAG_BYTES);
    if (ret != 0) {
        ocall_debug("integrity check failed");
        goto out;
    }

    *p_dirnode = dirnode;
    
    ret = 0;
out:
    if (ret) {
        my_free(dirnode);
    }

    mbedtls_gcm_free(&gcm_context);

    return ret;
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
