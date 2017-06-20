#include "seqptrmap.h"
#include "ucafs_sgx.h"

#include "siv/GCM_SIV.h"

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

/*
 * make sure key material is within the enclave
 */
int
enclave_siv_crypto(gcm_ekey_t * ekey,
                   gcm_tag_t * ekey_auth,
                   const shadow_t * uuid, /* the nonce */
                   const shadow_t * root_uuid, /* additional authenticated data */
                   uc_crypto_op_t op)
{
    int ret = 0;
    AES_GCM_SIV_CONTEXT siv_ctx;

    /* initialize the gcm SIV context */
    AES_GCM_SIV_Init(&siv_ctx, &__enclave_encryption_key__);

    if (op == UC_ENCRYPT) {
        AES_GCM_SIV_Encrypt(&siv_ctx, (uint8_t *)ekey, (uint8_t *)ekey_auth,
                            (uint8_t *)root_uuid, (const uint8_t *)ekey,
                            sizeof(shadow_t), sizeof(gcm_ekey_t),
                            (const uint8_t *)uuid,
                            (const uint8_t *)&__enclave_encryption_key__);
    } else {
        ret = AES_GCM_SIV_Decrypt(&siv_ctx, (uint8_t *)ekey,
                                  (uint8_t *)ekey_auth, (uint8_t *)root_uuid,
                                  (const uint8_t *)ekey, sizeof(shadow_t),
                                  sizeof(gcm_ekey_t), (const uint8_t *)uuid,
                                  (const uint8_t *)&__enclave_encryption_key__);
    }

    return ret;
}

crypto_ekey_t *
derive_skey(shadow_t * shdw1, shadow_t * shdw2)
{
    crypto_ekey_t * skey;
    mbedtls_sha256_context _, *sha256_ctx = &_;

    /* we are going to allocate enough buffer for the sha256 */
    skey = (crypto_ekey_t *)malloc(CONFIG_SHA256_BUFLEN);
    if (skey == NULL) {
        return NULL;
    }

    mbedtls_sha256_init(sha256_ctx);
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)&__enclave_encryption_key__,
            sizeof(crypto_ekey_t));
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)shdw1, sizeof(shadow_t));
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)shdw2, sizeof(shadow_t));
    mbedtls_sha256_finish(sha256_ctx, (uint8_t *)skey);
    mbedtls_sha256_free(sha256_ctx);


    return skey;
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
    uint8_t p_input[CONFIG_CRYPTO_BUFLEN], *p_data;

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

static inline int
usgx_dirnode_crypto(uc_dirnode_t * dirnode, uc_crypto_op_t op)
{
    int ret = -1, dirty_count = 0;
    dirnode_header_t * header = &dirnode->header;
    dirnode_bucket_entry_t * bucket_entry;
    uint8_t *p_input, *p_data;
    gcm_crypto_t _gcm, * gcm_crypto = &_gcm;
    gcm_ekey_t * ekey = &gcm_crypto->ekey;

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
            sgx_read_rand((uint8_t *)gcm_crypto, sizeof(gcm_crypto_t));
        } else {
            memcpy(gcm_crypto, &header->gcm_crypto, sizeof(gcm_crypto_t));
            /* decrypt the siv key */
            enclave_siv_crypto(ekey, &gcm_crypto->ekey_auth, &header->uuid,
                               &header->root, UC_DECRYPT);
        }
    } else {
        memcpy(gcm_crypto, &header->gcm_crypto, sizeof(gcm_crypto_t));
        /* unveril the encryption key */
        enclave_siv_crypto(ekey, &gcm_crypto->ekey_auth, &header->uuid,
                           &header->root, UC_DECRYPT);
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

    /* encrypt the metadata */
#if 0
    memcpy(&iv, &gcm_crypto->iv, sizeof(gcm_iv_t));

    mbedtls_gcm_context gcm_context;
    mbedtls_gcm_init(&gcm_context);
    mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES, (uint8_t *)ekey,
                       CONFIG_GCM_KEYBITS);
    mbedtls_gcm_starts(
        gcm_ctx, (op == UC_ENCRYPT ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT),
        (uint8_t *)&iv, sizeof(gcm_iv_t), NULL, 0);

    /* use the bucket and header information as additional data */


    mbedtls_gcm_finish(gcm_ctx, (uint8_t *)&tag, sizeof(gcm_tag_t));
    mbedtls_gcm_free(gcm_ctx);
#endif

    /* copy the encryption key into the dirnode */
    if (op == UC_ENCRYPT) {
        enclave_siv_crypto(ekey, &gcm_crypto->ekey_auth, &header->uuid,
                           &header->root, UC_ENCRYPT);
        memcpy(&header->gcm_crypto, gcm_crypto, sizeof(gcm_crypto_t));
    }

    ret = 0;
out:
    return ret;
}

int
ecall_dirnode_crypto(uc_dirnode_t * dirnode, uc_crypto_op_t op)
{
    return usgx_dirnode_crypto(dirnode, op);
}

static inline int
usgx_filebox_crypto(uc_filebox_t * filebox, uc_crypto_op_t op)
{
    int ret = 0, bytes_left, len,
        mode = (op == UC_ENCRYPT ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT);
    filebox_header_t * header = &filebox->header;
    crypto_ekey_t * sealing_key;
    gcm_crypto_t gcm_crypto;
    gcm_ekey_t *ekey = &gcm_crypto.ekey;
    gcm_iv_t iv;
    gcm_tag_t tag;
    uint8_t p_input[CONFIG_CRYPTO_BUFLEN], *p_data;
    mbedtls_gcm_context _gcm, *gcm_ctx = &_gcm;

    /* 2 - generate or extract the encryption key */
    if (op == UC_ENCRYPT) {
        sgx_read_rand((uint8_t *)&gcm_crypto, sizeof(gcm_crypto_t));
    } else {
        memcpy(&gcm_crypto, &header->gcm_crypto, sizeof(gcm_crypto_t));
        // unseal the crypto key
        enclave_siv_crypto(ekey, &gcm_crypto.ekey_auth, &header->uuid,
                           &header->root, UC_DECRYPT);
    }
    // copy the IV
    memcpy(&iv, &gcm_crypto.iv, sizeof(gcm_iv_t));

    /* 3 - Setup the gcm context */
    mbedtls_gcm_init(gcm_ctx);
    mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES, (uint8_t *)ekey,
                       CONFIG_GCM_KEYBITS);
    mbedtls_gcm_starts(gcm_ctx, mode, (uint8_t *)&iv, sizeof(gcm_iv_t),
                       (uint8_t *)header, FILEBOX_HEADER_SIZE_NOCRYPTO);

    /* 4 - encrypt and seal the filebox contents */
    p_data = filebox->payload; 
    bytes_left = header->fbox_payload_len;
    while (bytes_left > 0) {
        len = MIN(bytes_left, CONFIG_CRYPTO_BUFLEN);

        memcpy(p_input, p_data, len);

        mbedtls_gcm_update(gcm_ctx, len, p_input, p_data);

        p_data += len;
        bytes_left -= len;
    }

    mbedtls_gcm_finish(gcm_ctx, (uint8_t *)&tag, sizeof(gcm_tag_t));
    mbedtls_gcm_free(gcm_ctx);

    /* 5 - time for the results */
    if (op == UC_ENCRYPT) {
        memcpy(&gcm_crypto.tag, &tag, sizeof(gcm_tag_t));
        // seal the crypto key and send the result to E+
        enclave_siv_crypto(ekey, &gcm_crypto.ekey_auth, &header->uuid,
                           &header->root, UC_DECRYPT);
        memcpy(&header->gcm_crypto, &gcm_crypto, sizeof(gcm_crypto_t));
    } else {
        /* lets perform the decryption */
        if (memcmp(&tag, &gcm_crypto.tag, sizeof(gcm_tag_t))) {
            ret = E_ERROR_CRYPTO;
            goto out;
        }
    }

out:
    return ret;
}

int
ecall_filebox_crypto(uc_filebox_t * filebox, uc_crypto_op_t op)
{
    return usgx_filebox_crypto(filebox, op);
}
