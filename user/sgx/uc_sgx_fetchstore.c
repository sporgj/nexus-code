#include "enclave_private.h"
#include "seqptrmap.h"

typedef struct {
    uc_crypto_op_t op;
    size_t position;
    crypto_context_t crypto_ctx;
    crypto_iv_t ctx_iv;
    mbedtls_aes_context aes_ctx;
    mbedtls_md_context_t hmac_ctx;
    uint8_t * p_input;
    uint8_t * p_output;
    uint8_t nonce[16];
} enclave_context_t;

static struct seqptrmap * xfer_context_map = NULL;

/**
 * Starts the file crypto
 * @return 0 on success
 */
int
ecall_xfer_start(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_CRYPTO, off, i;
    uint8_t * iv;
    enclave_context_t __SECRET * __ctx;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    crypto_context_t * crypto_ctx, * file_crypto_ctx;
    uc_fbox_t * fbox = xfer_ctx->fbox;
    uc_crypto_op_t op = xfer_ctx->op;

    /* we can't simultaneously encrypt and decrypt */
    if ((op & UC_ENCRYPT) && (op & UC_DECRYPT)) {
        return E_ERROR_ERROR;
    }

    /* if you encrypt, you have to mac by force */
    if (op & UC_ENCRYPT) {
        op |= UC_VERIFY;
    }

    __ctx = (enclave_context_t *)calloc(1, sizeof(enclave_context_t));
    if (__ctx == NULL) {
        return E_ERROR_ALLOC;
    }

    /* 1 - copy the crypto data */
    crypto_ctx = &__ctx->crypto_ctx;
    file_crypto_ctx = &fbox->chunk0;

    if (op & UC_ENCRYPT) {
        /* The crypto context includes the mac. But since we're encrypting, its
         * value will be overriden when the context is closed */
        sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));
	memcpy(file_crypto_ctx, crypto_ctx, sizeof(crypto_context_t));
    } else {
        // initialize the cryptographic data
        memcpy(crypto_ctx, file_crypto_ctx, sizeof(crypto_context_t));
    }

    // unseal the encryption and mac keys
    enclave_crypto_ekey(&crypto_ctx->ekey, UC_DECRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_DECRYPT);

    memcpy(&__ctx->ctx_iv, &crypto_ctx->iv, sizeof(crypto_iv_t));

    /* 2 - initialize the cryptographic contexts */
    aes_ctx = &__ctx->aes_ctx;
    hmac_ctx = &__ctx->hmac_ctx;

    mbedtls_aes_init(aes_ctx);
    mbedtls_aes_setkey_enc(aes_ctx, (uint8_t *)&crypto_ctx->ekey,
                           CRYPTO_AES_KEY_SIZE_BITS);

    if (op & UC_VERIFY) {
        mbedtls_md_init(hmac_ctx);
        mbedtls_md_setup(hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                         1);
        mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                               sizeof(crypto_ekey_t));
    }

    if (xfer_context_map == NULL) {
        if ((xfer_context_map = seqptrmap_init()) == NULL) {
            error = E_ERROR_ALLOC;
            goto out;
        }
    }

    xfer_ctx->enclave_crypto_id = seqptrmap_add(xfer_context_map, __ctx);
    if (xfer_ctx->enclave_crypto_id == -1) {
        error = E_ERROR_HASHMAP;
        goto out;
    }

    __ctx->p_input = (uint8_t *)malloc(E_CRYPTO_BUFFER_LEN);
    if (__ctx->p_input == NULL) {
        error = E_ERROR_ALLOC;
        goto out;
    }

    /* compute the IV */
    if (op & UC_DECRYPT) {
        iv = __ctx->ctx_iv.bytes;
        off = xfer_ctx->position / CRYPTO_CRYPTO_BLK_SIZE;

        for (i = off; i > 0; i--) {
            if (++iv[CRYPTO_CRYPTO_BLK_SIZE - 1] == 0) {
                // let's carry over
                __carry_over(iv, CRYPTO_CRYPTO_BLK_SIZE - 2);
            }
        }
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
ecall_xfer_crypto(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, bytes_left;
    size_t nbytes;
    size_t * pos;
    uint8_t *p_in, *p_out, *p_buf, *nonce;
    crypto_iv_t * iv;
    enclave_context_t __SECRET * __ctx;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    uc_crypto_op_t op;

    __ctx = seqptrmap_get(xfer_context_map, xfer_ctx->enclave_crypto_id);
    if (__ctx == NULL) {
        return E_ERROR_HASHMAP;
    }

    op = __ctx->op;
    nonce = __ctx->nonce;
    iv = &__ctx->ctx_iv;
    aes_ctx = &__ctx->aes_ctx;
    hmac_ctx = &__ctx->hmac_ctx;

    pos = &__ctx->position;
    p_in = __ctx->p_input;
    p_out = __ctx->p_input;
    p_buf = xfer_ctx->buffer;

    bytes_left = xfer_ctx->valid_buflen;
    while (bytes_left > 0) {
        nbytes = MIN(bytes_left, E_CRYPTO_BUFFER_LEN);
        memcpy(p_in, p_buf, nbytes);

        if (op & UC_ENCRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, nbytes, pos, iv->bytes, nonce, p_in,
                                  p_out);
        }

        if (op & UC_VERIFY) {
            // XXX this might seem counterintuive but p_in == p_out (pointers)
            mbedtls_md_hmac_update(hmac_ctx, p_in, nbytes);
        }

        if (op & UC_DECRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, nbytes, pos, iv->bytes, nonce, p_in,
                                  p_out);
        }

        memcpy(p_buf, p_out, nbytes);

        bytes_left -= nbytes;
        p_buf += nbytes;
    }

    error = E_SUCCESS;
out:
    return error;
}

int ecall_xfer_finish(xfer_context_t * xfer_ctx, crypto_mac_t * dest_mac)
{
    int error = E_SUCCESS;
    crypto_mac_t mac, *ctx_mac;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    enclave_context_t __SECRET * __ctx;
    crypto_context_t * crypto_ctx;
    uc_crypto_op_t op;

    __ctx = seqptrmap_get(xfer_context_map, xfer_ctx->enclave_crypto_id);
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
        memcpy(dest_mac, &mac, sizeof(crypto_mac_t));
        error = E_SUCCESS;
    }

    if ((op & UC_ENCRYPT) || (op & UC_DECRYPT)) {
        mbedtls_aes_free(aes_ctx);
    }

    memset_s(__ctx, sizeof(enclave_context_t), 0, 1);
out:
    seqptrmap_delete(xfer_context_map, xfer_ctx->enclave_crypto_id);
    free(__ctx->p_input);
    free(__ctx);
    return error;
}
