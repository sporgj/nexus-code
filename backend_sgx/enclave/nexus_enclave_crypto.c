#include "nexus_trusted.h"

/**
 * Refactored function to apply key wrapping
 * TODO: add MAC'
 * @param key_encryption_key
 * @param sensitive_ekey
 * @param wrap whether to wrap or unwrap
 */
static int
__keywrap(uint8_t * key_encryption_key, uint8_t * sensitive_ekey, bool wrap)
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
    __keywrap(volumekey->bytes, (uint8_t *)&crypto_context->ekey, true);
}

static void
unwrap_crypto_context(struct crypto_context * crypto_context,
                      struct volumekey *      volumekey)
{
    __keywrap(volumekey->bytes, (uint8_t *)&crypto_context->ekey, false);
}

int
supernode_encryption(struct supernode *  supernode,
                     struct volumekey *  volumekey,
                     struct supernode ** p_sealed_supernode)
{
    struct supernode        * sealed_supernode = NULL;
    struct supernode_header * sealed_header    = NULL;

    struct supernode_header * header = &supernode->header;

    mbedtls_gcm_context     gcm_context;
    struct crypto_context * crypto_context      = NULL;
    uint8_t                 iv[CONFIG_IV_BYTES] = { 0 };

    int ret = -1;

    // TODO for now, we increment the supernode's version on every encryption
    // In the future, we need a "dirty" flag on supernodes
    header->version += 1;

    // copy the header information into the sealed_header
    {
        sealed_supernode = (struct supernode *)calloc(1, header->total_size);

        if (sealed_supernode == NULL) {
            header->version -= 1;
            ocall_debug("allocation error");
            return -1;
        }

        sealed_header = &sealed_supernode->header;
        memcpy(sealed_header, header, sizeof(struct supernode_header));
    }


    // initialize our crypto stuff
    mbedtls_gcm_init(&gcm_context);

    crypto_context = &sealed_supernode->crypto_context;


    {
        sgx_read_rand((uint8_t *)&crypto_context->ekey, sizeof(crypto_ekey_t));
        sgx_read_rand((uint8_t *)&crypto_context->iv, CONFIG_IV_BYTES);

        memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);


        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey,
                           CONFIG_EKEY_BITS);

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_ENCRYPT,
                           iv,
                           CONFIG_IV_BYTES,
                           (uint8_t *) sealed_header, // AAD used for integrity
                           sizeof(struct supernode_header));
    }


    // encrypt the usertable
    {
        size_t user_table_size = supernode->user_table.user_buflen
                                 + sizeof(struct volume_user_table);

        ret = mbedtls_gcm_update(&gcm_context,
                                 user_table_size,
                                 (uint8_t *)&supernode->user_table,
                                 (uint8_t *)&sealed_supernode->user_table);

        if (ret != 0) {
            ocall_debug("mbedtls_gcm_update() error on supernode");
            goto out;
        }
    }


    mbedtls_gcm_finish(
        &gcm_context, (uint8_t *)&crypto_context->tag, CONFIG_TAG_BYTES);

    // wrap the crypto context and send it out.
    keywrap_crypto_context(crypto_context, volumekey);

    *p_sealed_supernode = sealed_supernode;

    ret = 0;
out:
    if (ret) {
        header->version -= 1;

        my_free(sealed_supernode);
    }

    mbedtls_gcm_free(&gcm_context);

    return ret;
}

int
supernode_decryption(struct supernode *  sealed_supernode,
                     struct volumekey *  volumekey,
                     struct supernode ** p_supernode)
{
    struct supernode *        supernode     = NULL;
    struct supernode_header * header        = NULL;

    struct supernode_header * sealed_header = &sealed_supernode->header;

    mbedtls_gcm_context     gcm_context;
    struct crypto_context * crypto_context = NULL;
    uint8_t                 iv[CONFIG_IV_BYTES]   = { 0 };
    uint8_t                 tag[CONFIG_TAG_BYTES] = { 0 };

    int ret = -1;


    // copy the header and crypto context from the sealed supernode
    {
        supernode = (struct supernode *)calloc(1, sealed_header->total_size);

        if (supernode == NULL) {
            ocall_debug("allocation error");
            return -1;
        }

        header = &supernode->header;

        memcpy(header, sealed_header, sizeof(struct supernode_header));

        memcpy(&supernode->crypto_context,
               &sealed_supernode->crypto_context,
               sizeof(struct crypto_context));
    }


    mbedtls_gcm_init(&gcm_context);

    // unwrap the crypto context and start decrypting
    crypto_context = &supernode->crypto_context;
    unwrap_crypto_context(crypto_context, volumekey);


    {
        memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);

        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey,
                           CONFIG_EKEY_BITS);

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_DECRYPT,
                           iv,
                           CONFIG_IV_BYTES,
                           (uint8_t *) header, // AAD used for integrity
                           sizeof(struct supernode_header));
    }


    // decrypt the user table
    {
        size_t user_table_size = supernode->user_table.user_buflen
                                 + sizeof(struct volume_user_table);

        ret = mbedtls_gcm_update(&gcm_context,
                                 user_table_size,
                                 (uint8_t *)&supernode->user_table,
                                 (uint8_t *)&sealed_supernode->user_table);

        if (ret != 0) {
            ocall_debug("mbedtls_gcm_update() error on supernode");
            goto out;
        }
    }



    mbedtls_gcm_finish(&gcm_context, (uint8_t *)&tag, CONFIG_TAG_BYTES);

    if (memcmp(&tag, &sealed_supernode->crypto_context.tag, CONFIG_TAG_BYTES)) {
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
    uint8_t * sealed_buffer = (uint8_t *)&sealed_dirnode->entries;

    struct dirnode * dirnode = dirnode_wrapper->dirnode;

    struct dirnode_direntry_list * head      = &dirnode_wrapper->direntry_head;
    struct dirnode_direntry_item * entryitem = NULL;
    struct dirnode_direntry *      direntry  = NULL;

    size_t size = 0;
    int    ret  = -1;

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

int
dirnode_encryption(struct dirnode *         dirnode,
                   struct dirnode_wrapper * dirnode_wrapper,
                   struct volumekey *       volumekey,
                   struct dirnode **        p_sealed_dirnode)
{
    struct dirnode *        sealed_dirnode = NULL;
    struct dirnode_header * sealed_header  = NULL;

    struct dirnode_header * header = &dirnode->header;

    mbedtls_gcm_context     gcm_context;
    struct crypto_context * crypto_context      = NULL;
    uint8_t                 iv[CONFIG_IV_BYTES] = { 0 };

    int ret = -1;


    // increment the version of header
    header->version += 1;

    {
        sealed_dirnode = (struct dirnode *)calloc(1, header->total_size);
        if (sealed_dirnode == NULL) {
            ocall_print("allocation error");
            header->version -= 1;
            return -1;
        }

        sealed_header = &sealed_dirnode->header;
        memcpy(sealed_header, header, sizeof(struct dirnode_header));
    }


    // initialize the crypto stuff
    mbedtls_gcm_init(&gcm_context);

    crypto_context = &sealed_dirnode->crypto_context;


    {
        sgx_read_rand((uint8_t *)&crypto_context->ekey, sizeof(crypto_ekey_t));
        sgx_read_rand((uint8_t *)&crypto_context->iv, CONFIG_IV_BYTES);

        memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);


        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey,
                           CONFIG_EKEY_BITS);

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_ENCRYPT,
                           iv,
                           CONFIG_IV_BYTES,
                           (uint8_t *) sealed_header, // AAD used for integrity
                           sizeof(struct dirnode_header));
    }


    // encrypt the directory entries
    if (dirnode_wrapper != NULL && sealed_dirnode->header.dir_size > 0) {
        ret = _encrypt_dirnode_direntries(
            dirnode_wrapper, sealed_dirnode, &gcm_context);

        if (ret != 0) {
            ocall_debug("_encrypt_dirnode_direntries() FAILED");
            goto out;
        }
    }


    // wrap the crypto context and send it out.
    mbedtls_gcm_finish(
        &gcm_context, (uint8_t *)&crypto_context->tag, CONFIG_TAG_BYTES);

    keywrap_crypto_context(crypto_context, volumekey);

    *p_sealed_dirnode = sealed_dirnode;

    ret = 0;
out:
    if (ret != 0) {
        my_free(sealed_dirnode);

        header->version -= 1;
    }

    mbedtls_gcm_free(&gcm_context);

    return ret;
}

int
dirnode_encryption_with_wrapper(struct dirnode_wrapper * dirnode_wrapper,
                                struct dirnode **        p_sealed_dirnode)
{
    return dirnode_encryption(dirnode_wrapper->dirnode,
                              dirnode_wrapper,
                              dirnode_wrapper->volumekey,
                              p_sealed_dirnode);
}

int
dirnode_decryption(struct dirnode *   sealed_dirnode,
                   struct volumekey * volumekey,
                   struct dirnode **  p_dirnode)
{
    struct dirnode *        dirnode        = NULL;
    struct dirnode_header * header         = NULL;

    struct dirnode_header * sealed_header  = &sealed_dirnode->header;

    mbedtls_gcm_context     gcm_context;
    struct crypto_context * crypto_context        = NULL;
    uint8_t                 iv[CONFIG_IV_BYTES]   = { 0 };
    uint8_t                 tag[CONFIG_TAG_BYTES] = { 0 };

    int ret = -1;


    // allocate the necessary memory and start copying header information
    {
        dirnode = (struct dirnode *)calloc(1, sealed_header->total_size);

        if (dirnode == NULL) {
            ocall_print("allocation error");
            return -1;
        }

        header = &dirnode->header;

        memcpy(header, sealed_header, sizeof(struct dirnode_header));

        memcpy(&dirnode->crypto_context,
               &sealed_dirnode->crypto_context,
               sizeof(struct crypto_context));
    }


    mbedtls_gcm_init(&gcm_context);

    crypto_context = &dirnode->crypto_context;
    unwrap_crypto_context(crypto_context, volumekey);


    // initilize the decryption context and decrypt the direntry contents
    {

        memcpy(iv, &crypto_context->iv, CONFIG_IV_BYTES);

        mbedtls_gcm_setkey(&gcm_context,
                           MBEDTLS_CIPHER_ID_AES,
                           (uint8_t *)&crypto_context->ekey,
                           CONFIG_EKEY_BITS);

        mbedtls_gcm_starts(&gcm_context,
                           MBEDTLS_GCM_DECRYPT,
                           iv,
                           CONFIG_IV_BYTES,
                           (uint8_t *) header, // AAD used for integrity
                           sizeof(struct dirnode_header));

    }



    // decrypt the user table
    {
        ret = mbedtls_gcm_update(&gcm_context,
                header->dir_size,
                (uint8_t *)&sealed_dirnode->entries,
                (uint8_t *)&dirnode->entries);

        if (ret != 0) {
            ocall_debug("mbedtls_gcm_update() error on supernode");
            goto out;
        }
    }



    // compute mac anc compare the results
    mbedtls_gcm_finish(&gcm_context, (uint8_t *)&tag, CONFIG_TAG_BYTES);

    if (memcmp(&tag, &sealed_dirnode->crypto_context.tag, CONFIG_TAG_BYTES)) {
        ocall_debug("dirnode integrity check failed");
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

int
volumekey_wrap(struct volumekey * volumekey)
{
    return __keywrap((uint8_t *)&enclave_sealing_key, volumekey->bytes, true);
}

int
volumekey_unwrap(struct volumekey * volumekey)
{
    return __keywrap((uint8_t *)&enclave_sealing_key, volumekey->bytes, false);
}
