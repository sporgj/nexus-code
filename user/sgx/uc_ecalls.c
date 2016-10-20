#include "enclave_private.h"
#include "seqptrmap.h"

sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;

typedef struct {
    uc_crypto_op_t op;
    size_t position;
    crypto_context_t crypto_ctx;
    crypto_iv_t ctx_iv;
    mbedtls_aes_context aes_ctx;
    mbedtls_md_context_t hmac_ctx;
    uint8_t * p_input;
    uint8_t * p_output;
} enclave_context_t;

struct seqptrmap * crypto_hashmap = NULL;

int
ecall_init_enclave()
{
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

    if ((crypto_hashmap = seqptrmap_init()) == NULL) {
        ret = E_ERROR_HASHMAP;
        goto out;
    }

    ret = E_SUCCESS;
out:
    return ret;
#endif
    memset(&__enclave_encryption_key__, 0, sizeof(sgx_key_128bit_t));
    return 0;
}

/**
 * Starts the file crypto
 * @return 0 on success
 */
int
ecall_init_crypto(xfer_context_t * xfer_ctx, crypto_context_t * file_crypto_ctx)
{
    int error = E_ERROR_CRYPTO;
    enclave_context_t __SECRET * __ctx;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    crypto_context_t * crypto_ctx;
    uc_crypto_op_t op = xfer_ctx->op;

    /* we can't simultaneously encrypt and decrypt */
    if ((op & UC_ENCRYPT) && (op & UC_DECRYPT)) {
        return E_ERROR_ERROR;
    }

    __ctx = (enclave_context_t *)calloc(1, sizeof(enclave_context_t));
    if (__ctx == NULL) {
        return E_ERROR_ALLOC;
    }

    /* 1 - copy the crypto data */
    crypto_ctx = &__ctx->crypto_ctx;
    if (xfer_ctx->op & UC_ENCRYPT) {
        /* The crypto context includes the mac. But since we're encrypting, its
         * value will be overriden when the context is closed */
        sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));
    } else {
        // initialize the cryptographic data
        memcpy(crypto_ctx, file_crypto_ctx, sizeof(crypto_context_t));

        // unseal the encryption and mac keys
        enclave_crypto_ekey(&crypto_ctx->ekey, UC_DECRYPT);
        enclave_crypto_ekey(&crypto_ctx->mkey, UC_DECRYPT);
    }

    memcpy(&__ctx->ctx_iv, &crypto_ctx->iv, sizeof(crypto_iv_t));

    /* 2 - initialize the cryptographic contexts */
    aes_ctx = &__ctx->aes_ctx;
    hmac_ctx = &__ctx->hmac_ctx;

    mbedtls_aes_init(aes_ctx);
    if (op & UC_ENCRYPT) {
        mbedtls_aes_setkey_enc(aes_ctx, (uint8_t *)&crypto_ctx->ekey,
                               CRYPTO_AES_KEY_SIZE_BITS);
    } else if (op & UC_DECRYPT) {
        mbedtls_aes_setkey_dec(aes_ctx, (uint8_t *)&crypto_ctx->ekey,
                               CRYPTO_AES_KEY_SIZE_BITS);
    }

    mbedtls_md_init(hmac_ctx);
    mbedtls_md_setup(hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                           CRYPTO_MAC_KEY_SIZE_BITS);

    xfer_ctx->enclave_crypto_id = seqptrmap_add(crypto_hashmap, __ctx);
    if (xfer_ctx->enclave_crypto_id == -1) {
        error = E_ERROR_HASHMAP;
        goto out;
    }

    __ctx->p_input = (uint8_t *)malloc(E_CRYPTO_BUFFER_LEN);
    if (__ctx->p_input == NULL) {
        error = E_ERROR_ALLOC;
        goto out;
    }

    __ctx->op = op;

    error = E_SUCCESS;
out:
    if (error) {
        if (__ctx->p_input)
            free(__ctx->p_input);
        free(__ctx);
    }
    return error;
}

int
ecall_crypt_data(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, bytes_left;
    size_t nbytes; 
    size_t * pos;
    uint8_t *p_in, *p_out, *p_buf;
    crypto_iv_t * iv;
    enclave_context_t __SECRET * __ctx;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    uc_crypto_op_t op;

    __ctx = seqptrmap_get(crypto_hashmap, xfer_ctx->enclave_crypto_id);
    if (__ctx == NULL) {
        return E_ERROR_HASHMAP;
    }

    op = __ctx->op;
    iv = &__ctx->ctx_iv;
    aes_ctx = &__ctx->aes_ctx;
    hmac_ctx = &__ctx->hmac_ctx;

    pos = &__ctx->position;
    p_in = __ctx->p_input;
    p_out = __ctx->p_input;
    p_buf = xfer_ctx->buffer;

    bytes_left = xfer_ctx->valid_buflen;
    while (bytes_left > 0) {
        nbytes = bytes_left > E_CRYPTO_BUFFER_LEN ? E_CRYPTO_BUFFER_LEN
                                                  : bytes_left;
        memcpy(p_in, p_buf, nbytes);

        if (op & UC_ENCRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, nbytes, pos, iv->nonce, iv->block,
                                  p_in, p_out);
        }

        if (op & UC_VERIFY) {
            // XXX this might seem counterintuive but p_in == p_out (pointers)
            mbedtls_md_hmac_update(hmac_ctx, p_in, nbytes);
        }

        if (op & UC_DECRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, nbytes, pos, iv->nonce, iv->block,
                                  p_in, p_out);
        }

        memcpy(p_buf, p_out, nbytes);

        bytes_left -= nbytes;
        p_buf += nbytes;
    }

    error = E_SUCCESS;
out:
    return error;
}

int
ecall_finish_crypto(xfer_context_t * xfer_ctx, crypto_context_t * fcrypto)
{
    int error = E_SUCCESS;
    crypto_mac_t mac, *ctx_mac;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    enclave_context_t __SECRET * __ctx;
    crypto_context_t * crypto_ctx;
    uc_crypto_op_t op;

    __ctx = seqptrmap_get(crypto_hashmap, xfer_ctx->enclave_crypto_id);
    if (__ctx == NULL) {
        return E_ERROR_HASHMAP;
    }

    op = __ctx->op;
    aes_ctx = &__ctx->aes_ctx;
    hmac_ctx = &__ctx->hmac_ctx;
    crypto_ctx = &__ctx->crypto_ctx;
    ctx_mac = &crypto_ctx->mac;

    /* close the crypto context and verify the mac */
    if (op & UC_VERIFY) {
        mbedtls_md_hmac_finish(hmac_ctx, (uint8_t *)&mac);
        mbedtls_md_free(hmac_ctx);

        error = memcmp(ctx_mac, &mac, sizeof(crypto_mac_t)) ? E_ERROR_ERROR : 0;
    }

    /* if we're encrypting, we need to reseal everything and send it over */
    if (op & UC_ENCRYPT) {
        memcpy(ctx_mac, &mac, sizeof(crypto_mac_t));
        enclave_crypto_ekey(&crypto_ctx->ekey, UC_ENCRYPT);
        enclave_crypto_ekey(&crypto_ctx->mkey, UC_ENCRYPT);

        memcpy(fcrypto, &crypto_ctx, sizeof(crypto_context_t));
    }

    if ((op & UC_ENCRYPT) || (op & UC_DECRYPT)) {
        mbedtls_aes_free(aes_ctx);
    }

    memset_s(__ctx, sizeof(enclave_context_t), 0, 1);
out:
    seqptrmap_delete(crypto_hashmap, xfer_ctx->enclave_crypto_id);
    free(__ctx->p_input);
    free(__ctx);
    return error;
}

int
ecall_crypto_dirnode(dnode_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    return crypto_metadata(&header->crypto_ctx, header->protolen, data, op);
}

int
ecall_crypto_filebox(fbox_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    return crypto_metadata(&header->crypto_ctx, header->protolen, data, op);
}
