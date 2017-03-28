#include "seqptrmap.h"
#include "ucafs_sgx.h"

sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;
crypto_ekey_t * __enclave_key__ = (crypto_ekey_t *)&__enclave_encryption_key__;

auth_struct_t enclave_auth_data = { 0 };

int
ecall_init_enclave()
{
    sgx_report_t report;
#if 0
    /* uncomment this when ready to push */
    sgx_key_request_t request;
    sgx_status_t status;
    int ret;

    memset(&request, 0, sizeof(sgx_key_request_t));
    request.key_name = SGX_KEYSELECT_SEAL;
    request.key_policy = SGX_KEYPOLICY_MRSIGNER;
    request.attribute_mask.flags = 0xfffffffffffffff3ULL;
    request.attribute_mask.xfrm = 0;

    status = sgx_get_key(&request, &__enclave_encryption_key__);
    if (status != SGX_SUCCESS) {
        ret = E_ERROR_KEYINIT;
        goto out;
    }

    ret = E_SUCCESS;
out:
    return ret;
#endif

    /* lets generate our random nonce */
    sgx_read_rand(enclave_auth_data.nonce, sizeof(enclave_auth_data.nonce));
    if (sgx_create_report(NULL, NULL, &report) != SGX_SUCCESS) {
        return -1;
    }

    /* copy our enclave signature */
    memcpy(&enclave_auth_data.mrenclave, &report.body.mr_enclave,
           sizeof(sgx_measurement_t));

    memset(&__enclave_encryption_key__, 0, sizeof(sgx_key_128bit_t));

    return 0;
}

crypto_ekey_t *
derive_skey2(crypto_ekey_t * rkey, shadow_t * shdw1, shadow_t * shdw2)
{
    crypto_ekey_t * skey;
    mbedtls_sha256_context _, *sha256_ctx = &_;

    /* we are going to allocate enough buffer for the sha256 */
    skey = (crypto_ekey_t *)malloc(CONFIG_SHA256_BUFLEN);
    if (skey == NULL) {
        return NULL;
    }

    mbedtls_sha256_init(sha256_ctx);
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)rkey, sizeof(crypto_ekey_t));
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)shdw1, sizeof(shadow_t));
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)shdw2, sizeof(shadow_t));
    mbedtls_sha256_finish(sha256_ctx, (uint8_t *)skey);
    mbedtls_sha256_free(sha256_ctx);

    return skey;
}

crypto_ekey_t *
derive_skey1(shadow_t * root, shadow_t * shdw1, shadow_t * shdw2)
{
    supernode_t * super;

    /* find the supernode */
    if ((super = find_supernode(root)) == NULL) {
        return NULL;
    }

    return derive_skey2(&super->crypto_ctx.ekey, shdw1, shdw2);
}

int
enclave_crypto_ekey(crypto_ekey_t * ekey,
                    crypto_ekey_t * sealing_key,
                    uc_crypto_op_t op)
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (op == UC_ENCRYPT) {
        mbedtls_aes_setkey_enc(&ctx, (uint8_t *)sealing_key,
                               CRYPTO_AES_KEY_SIZE_BITS);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (uint8_t *)ekey,
                              (uint8_t *)ekey);
    } else {
        mbedtls_aes_setkey_dec(&ctx, (uint8_t *)sealing_key,
                               CRYPTO_AES_KEY_SIZE_BITS);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, (uint8_t *)ekey,
                              (uint8_t *)ekey);
    }

    mbedtls_aes_free(&ctx);

    return 0;
}

static int
crypto_metadata(crypto_context_t * p_ctx,
                crypto_ekey_t * sealing_key,
                void * header,
                size_t header_len,
                uint8_t * data,
                size_t data_len,
                uc_crypto_op_t op)
{
    int error = E_ERROR_ERROR, bytes_left, len;
    size_t off = 0;
    mbedtls_aes_context aes_ctx;
    mbedtls_md_context_t hmac_ctx;
    uint8_t *p_input = NULL, *p_output = NULL, *p_data;
    crypto_context_t crypto_ctx;
    crypto_mac_t mac;
    crypto_iv_t iv;
    crypto_ekey_t _CONFIDENTIAL *_ekey, *_mkey;
    uint8_t stream_block[16] = { 0 };

    p_input = (uint8_t *)malloc(E_CRYPTO_BUFFER_LEN);
    if (p_input == NULL) {
        return E_ERROR_ERROR;
    }

    p_output = p_input;

    /* gather the cryptographic information */
    memcpy(&crypto_ctx, p_ctx, sizeof(crypto_context_t));

    _ekey = &crypto_ctx.ekey;
    _mkey = &crypto_ctx.mkey;

    if (op == UC_ENCRYPT) {
        /* then we've to generate a new key/IV pair */
        sgx_read_rand((uint8_t *)&crypto_ctx, sizeof(crypto_context_t));
    } else {
        /* unseal our encryption key */
        enclave_crypto_ekey(_ekey, sealing_key, UC_DECRYPT);
        enclave_crypto_ekey(_mkey, sealing_key, UC_DECRYPT);
    }

    memcpy(&iv, &crypto_ctx.iv, sizeof(crypto_iv_t));

    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, (uint8_t *)_ekey,
                           CRYPTO_AES_KEY_SIZE_BITS);

    mbedtls_md_init(&hmac_ctx);
    mbedtls_md_setup(&hmac_ctx, HMAC_TYPE, 1);
    mbedtls_md_hmac_starts(&hmac_ctx, (uint8_t *)_mkey, CRYPTO_MAC_KEY_SIZE);

    /* lets hmac the header */
    mbedtls_md_hmac_update(&hmac_ctx, header, header_len);

    p_data = data;
    bytes_left = data_len;

    while (bytes_left > 0) {
        len = MIN(bytes_left, E_CRYPTO_BUFFER_LEN);

        memcpy(p_input, p_data, len);

        if (op == UC_ENCRYPT) {
            mbedtls_aes_crypt_ctr(&aes_ctx, len, &off, iv.bytes, stream_block,
                                  p_input, p_output);

            mbedtls_md_hmac_update(&hmac_ctx, p_output, len);
        } else {
            mbedtls_md_hmac_update(&hmac_ctx, p_input, len);

            mbedtls_aes_crypt_ctr(&aes_ctx, len, &off, iv.bytes, stream_block,
                                  p_input, p_output);
        }

        memcpy(p_data, p_output, len);

        p_data += len;
        bytes_left -= len;
    }

    error = E_SUCCESS;

    if (op == UC_ENCRYPT) {
        mbedtls_md_hmac_finish(&hmac_ctx, (uint8_t *)&crypto_ctx.mac);
        // seal the encryption key
        enclave_crypto_ekey(_ekey, sealing_key, UC_ENCRYPT);
        enclave_crypto_ekey(_mkey, sealing_key, UC_ENCRYPT);
        memcpy(p_ctx, &crypto_ctx, sizeof(crypto_context_t));
    } else {
        mbedtls_md_hmac_finish(&hmac_ctx, (uint8_t *)&mac);
        error = memcmp(&mac, &crypto_ctx.mac, sizeof(crypto_mac_t));
    }

    mbedtls_aes_free(&aes_ctx);
    mbedtls_md_free(&hmac_ctx);
    free(p_input);

    return error;
}

inline int
usgx_crypto_dirnode(dnode_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    int ret;
    supernode_t * super;
    crypto_ekey_t * sealing_key;
    shadow_t * shdw_name;
    size_t total = header->dirbox_len + header->lockbox_len;

    /* super_ekey + root_shdw + fnode_uuid */
    sealing_key = derive_skey1(&header->root, &header->parent, &header->uuid);
    if (sealing_key == NULL) {
        return -1;
    }

    ret = crypto_metadata(&header->crypto_ctx, sealing_key, header,
                           sizeof(dnode_header_t) - sizeof(crypto_context_t),
                           data, total, op);
    free(sealing_key);
    return ret;
}

int
ecall_crypto_dirnode(dnode_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    return usgx_crypto_dirnode(header, data, op);
}

inline int
usgx_crypto_filebox(fbox_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    int ret;
    crypto_ekey_t * sealing_key;
    crypto_context_t crypto_ctx;

    /* super_ekey + root_shdw + fnode_uuid */
    sealing_key = derive_skey1(&header->root, &header->root, &header->uuid);
    if (sealing_key == NULL) {
        return -1;
    }

    ret = crypto_metadata(&header->crypto_ctx, sealing_key, header,
                           sizeof(fbox_header_t) - sizeof(crypto_context_t),
                           data, header->fbox_len, op);

    free(sealing_key);
    return ret;
}

int
ecall_crypto_filebox(fbox_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    return usgx_crypto_filebox(header, data, op);
}

static int
crypto_dirnode_buffer(dirnode_header_t * header,
                      gcm_ekey_t * ekey,
                      dirnode_bucket_entry_t * bucket_entry,
                      uc_crypto_op_t op)
{
    int ret = 0,
        md = (op == UC_ENCRYPT) ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
        bytes_left, len;
    gcm_iv_t iv;
    gcm_tag_t tag;
    mbedtls_gcm_context _, *gcm_ctx = &_;
    uint8_t p_input[CONFIG_CRYPTO_BUFLEN], p_out[CONFIG_CRYPTO_BUFLEN], *p_data;

    if (op == UC_ENCRYPT) {
        sgx_read_rand((uint8_t *)&bucket_entry->bckt.iv, sizeof(gcm_iv_t));
    }

    memcpy(&iv, &bucket_entry->bckt.iv, sizeof(gcm_iv_t));

    /* start the encryption */
    mbedtls_gcm_init(gcm_ctx);
    mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES, (uint8_t *)ekey,
                       CONFIG_GCM_KEYBITS);

    mbedtls_gcm_starts(gcm_ctx, md, (uint8_t *)&iv, sizeof(gcm_iv_t), NULL, 0);
    /*(uint8_t *)header,
                       offsetof(dirnode_header_t, ekey) */
    /* now encrypt the buffer */
    p_data = bucket_entry->buffer;
    bytes_left = bucket_entry->bckt.length;
    while (bytes_left > 0) {
        len = MIN(bytes_left, CONFIG_CRYPTO_BUFLEN);

        memcpy(p_input, p_data, len);

        mbedtls_gcm_update(gcm_ctx, len, p_input, p_data);

        p_data += len;
        bytes_left -= len;
    }

    mbedtls_gcm_finish(gcm_ctx, (uint8_t *)&tag, sizeof(gcm_tag_t));
    mbedtls_gcm_free(gcm_ctx);

    /* just */
    if (op == UC_ENCRYPT) {
        memcpy(&bucket_entry->bckt.tag, &tag, sizeof(gcm_tag_t));
    } else {
        ret = memcmp(&tag, &bucket_entry->bckt.tag, sizeof(gcm_tag_t));
    }

    return ret;
}

inline int
usgx_dirnode_crypto(uc_dirnode_t * dirnode, uc_crypto_op_t op)
{
    int ret = -1, dirty_count = 0;
    crypto_ekey_t * sealing_key;
    dirnode_header_t * header = &dirnode->header;
    gcm_ekey_t _ekey, *ekey = &_ekey;
    dirnode_bucket_entry_t * bucket_entry;
    uint8_t *p_input, *p_data;

    /* super_ekey + root_shdw + fnode_uuid */
    sealing_key = derive_skey1(&header->root, &header->parent, &header->uuid);
    if (sealing_key == NULL) {
        return -1;
    }

    /* now unseal the crypto key */
    if (op == UC_ENCRYPT) {
        TAILQ_FOREACH(bucket_entry, &dirnode->buckets, next_entry)
        {
            if (!bucket_entry->is_dirty) {
                continue;
            }

            dirty_count++;
        }

        if (dirty_count == dirnode->header.bucket_count) {
            sgx_read_rand((uint8_t *)ekey, sizeof(gcm_ekey_t));
        } else {
            memcpy(ekey, &dirnode->header.ekey, sizeof(gcm_ekey_t));
            enclave_crypto_ekey((crypto_ekey_t *)ekey, sealing_key, UC_DECRYPT);
        }
    } else {
        memcpy(ekey, &dirnode->header.ekey, sizeof(gcm_ekey_t));
        enclave_crypto_ekey((crypto_ekey_t *)ekey, sealing_key, UC_DECRYPT);
    }

    /* iterate the buffer entries and encrypt them */
    TAILQ_FOREACH(bucket_entry, &dirnode->buckets, next_entry)
    {
        if (op == UC_ENCRYPT && !bucket_entry->is_dirty) {
            continue;
        }

        if (crypto_dirnode_buffer(header, ekey, bucket_entry, op)) {
            goto out;
        }
    }

    /* copy the encryption key into the dirnode */
    if (op == UC_ENCRYPT) {
        enclave_crypto_ekey((crypto_ekey_t *)ekey, sealing_key, UC_ENCRYPT);
        memcpy(&dirnode->header.ekey, ekey, sizeof(gcm_ekey_t));
    }

    ret = 0;
out:
    free(sealing_key);
    return ret;
}

int
ecall_dirnode_crypto(uc_dirnode_t * dirnode, uc_crypto_op_t op)
{
    return usgx_dirnode_crypto(dirnode, op);
}
