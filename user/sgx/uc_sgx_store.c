#include "enclave_private.h"
#include "seqptrmap.h"

#define HMAC_TYPE mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)

typedef struct {
    uc_xfer_op_t xfer_op;
    int chunk_num;
    size_t pos;
    crypto_iv_t _iv;
    crypto_context_t curr_crypto_ctx;
    mbedtls_aes_context aes_ctx;
    mbedtls_md_context_t hmac_ctx;
    uint8_t nonce[16];
    uint8_t * input_buffer;
    uint8_t * output_buffer;
    uc_fbox_header_t fbox_hdr;
} enclave_context_t;

static struct seqptrmap * xfer_context_map = NULL;

static void
free_enclave_context(enclave_context_t * context)
{
    free(context->input_buffer);
    free(context);
}

int
ecall_store_init(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_CRYPTO;
    enclave_context_t __SECRET * context = NULL;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;

    context = (enclave_context_t *)calloc(1, sizeof(enclave_context_t));
    if (context == NULL) {
        return E_ERROR_ALLOC;
    }

    context->input_buffer = context->output_buffer
        = malloc(E_CRYPTO_BUFFER_LEN);
    if (context->input_buffer == NULL) {
        free(context);
        return E_ERROR_ALLOC;
    }

    context->xfer_op = xfer_ctx->xfer_op;
    context->chunk_num = xfer_ctx->chunk_num;

    /* initialize the crypto contexts */
    aes_ctx = &context->aes_ctx;
    mbedtls_aes_init(aes_ctx);

    hmac_ctx = &context->hmac_ctx;
    mbedtls_md_init(hmac_ctx);
    mbedtls_md_setup(hmac_ctx, HMAC_TYPE, 1);

    if (xfer_context_map == NULL
        && (xfer_context_map = seqptrmap_init()) == NULL) {
        error = E_ERROR_ALLOC;
        goto out;
    }

    xfer_ctx->enclave_crypto_id = seqptrmap_add(xfer_context_map, context);
    if (xfer_ctx->enclave_crypto_id == -1) {
        error = E_ERROR_HASHMAP;
        goto out;
    }

    error = E_SUCCESS;
out:
    if (error) {
        free_enclave_context(context);
    }

    return error;
}

int
ecall_store_start(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, file_size = xfer_ctx->total_len;
    uc_fbox_header_t * fbox_hdr;
    crypto_context_t * crypto_ctx;
    enclave_context_t * context;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;

    context = (enclave_context_t *)seqptrmap_get(xfer_context_map,
                                                 xfer_ctx->enclave_crypto_id);
    if (context == NULL) {
        return error;
    }

    /* copy the fbox information */
    fbox_hdr = &context->fbox_hdr;
    memcpy(fbox_hdr, xfer_ctx->fbox, sizeof(uc_fbox_header_t));
    fbox_hdr->chunk_count = FBOX_CHUNK_COUNT(file_size);
    fbox_hdr->chunk_size = UCAFS_CHUNK_SIZE;
    fbox_hdr->fbox_len = FBOX_SIZE(file_size);
    fbox_hdr->file_size = file_size;

    // TODO instantiate crypto data for fbox here

    /* generate the crypto data */
    crypto_ctx = &context->curr_crypto_ctx;
    sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));
    memcpy(&context->_iv, &crypto_ctx->iv, sizeof(crypto_iv_t));

    /* initialize the crypto stuff here */
    aes_ctx = &context->aes_ctx;
    hmac_ctx = &context->hmac_ctx;

    mbedtls_aes_setkey_enc(aes_ctx, (uint8_t *)&crypto_ctx->ekey,
                           CRYPTO_AES_KEY_SIZE_BITS);
    mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                           sizeof(crypto_ekey_t));

    return E_SUCCESS;
}

int
ecall_store_crypto(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, nbytes, bytes_left;
    crypto_context_t * crypto_ctx;
    enclave_context_t * context;
    uint8_t *p_in, *p_out, *p_buf, *nonce;
    crypto_iv_t * iv;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;

    context = (enclave_context_t *)seqptrmap_get(xfer_context_map,
                                                 xfer_ctx->enclave_crypto_id);
    if (context == NULL) {
        return error;
    }

    crypto_ctx = &context->curr_crypto_ctx;
    iv = &context->_iv;
    p_in = context->input_buffer, p_out = context->output_buffer,
    p_buf = xfer_ctx->buffer;
    aes_ctx = &context->aes_ctx;
    hmac_ctx = &context->hmac_ctx;
    nonce = context->nonce;

    bytes_left = xfer_ctx->valid_buflen;
    while (bytes_left > 0) {
        nbytes = MIN(bytes_left, E_CRYPTO_BUFFER_LEN);
        memcpy(p_in, p_buf, nbytes);

        mbedtls_aes_crypt_ctr(aes_ctx, nbytes, &context->pos, iv->bytes, nonce, p_in,
                              p_out);

	mbedtls_md_hmac_update(hmac_ctx, p_in, nbytes);

        memcpy(p_buf, p_out, nbytes);

        bytes_left -= nbytes;
        p_buf += nbytes;
    }

    return E_SUCCESS;
}

int ecall_store_finish(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, len, bytes_left;
    crypto_context_t * crypto_ctx, * dest_crypto_ctx;
    enclave_context_t * context;
    mbedtls_aes_context * aes_ctx;
    mbedtls_md_context_t * hmac_ctx;
    crypto_mac_t * mac;

    context = (enclave_context_t *)seqptrmap_get(xfer_context_map,
                                                 xfer_ctx->enclave_crypto_id);
    if (context == NULL) {
        return error;
    }

    crypto_ctx = &context->curr_crypto_ctx;
    aes_ctx = &context->aes_ctx;
    hmac_ctx = &context->hmac_ctx;
    mac = &context->curr_crypto_ctx.mac;

    /* compute the mac and call it a day */
    mbedtls_md_hmac_finish(hmac_ctx, (uint8_t *)mac);
    mbedtls_md_free(hmac_ctx);
    mbedtls_aes_free(aes_ctx);

    /* now seal everything and send it over */
    enclave_crypto_ekey(&crypto_ctx->ekey, UC_ENCRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_ENCRYPT);

    memcpy(&context->fbox_hdr, xfer_ctx->fbox, sizeof(uc_fbox_header_t));
    dest_crypto_ctx = &xfer_ctx->fbox->chunks[context->chunk_num];
    memcpy(dest_crypto_ctx, crypto_ctx, sizeof(crypto_context_t));

    aes_ctx = &context->aes_ctx;
    hmac_ctx = &context->hmac_ctx;

    seqptrmap_delete(xfer_context_map, xfer_ctx->enclave_crypto_id);
    free_enclave_context(context);
    return E_SUCCESS;
}
