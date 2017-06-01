#include "seqptrmap.h"
#include "ucafs_sgx.h"
#include "uc_fetchstore.h"
#include "uc_filebox.h"

static struct seqptrmap * xfer_context_map = NULL;

typedef struct {
    uc_xfer_op_t xfer_op;
    int chunk_num;
    size_t chunk_left;
    gcm_iv_t _iv;
    gcm_crypto_t gcm_crypto;
    mbedtls_gcm_context gcm_ctx;
    uint8_t * input_buffer;
    crypto_ekey_t * sealing_key;
} enclave_context_t;

static void
free_enclave_context(enclave_context_t * context)
{
    free(context->input_buffer);
    free(context);
}

int
ecall_xfer_init(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_CRYPTO,
        mode = (xfer_ctx->xfer_op == UCAFS_STORE ? MBEDTLS_GCM_ENCRYPT
                                                : MBEDTLS_GCM_DECRYPT);
    enclave_context_t * context;
    mbedtls_gcm_context * gcm_ctx;
    gcm_crypto_t * gcm_crypto;
    const gcm_crypto_t * gcm_crypto1;
    gcm_ekey_t * ekey;
    uc_filebox_t * filebox;
    filebox_header_t * header;

    /* create the enclave context */
    context = (enclave_context_t *)calloc(1, sizeof(enclave_context_t));
    if (context == NULL) {
        return E_ERROR_ALLOC;
    }

    /* initialize context variables */
    context->input_buffer = malloc(E_CRYPTO_BUFFER_LEN);
    if (context->input_buffer == NULL) {
        free(context);
        return E_ERROR_ALLOC;
    }

    /* the chunk size left */
    context->xfer_op = xfer_ctx->xfer_op;
    context->chunk_left = UCAFS_CHUNK_SIZE;

    /* initialize the crypto contexts */
    filebox = xfer_ctx->filebox;
    header = &xfer_ctx->filebox->header;
    gcm_crypto = &context->gcm_crypto;
    ekey = &gcm_crypto->ekey;

    // derive the sealing key
    context->sealing_key= derive_skey1(&header->root, &header->root, &header->uuid);
    if (context->sealing_key == NULL) {
        return E_ERROR_CRYPTO;
    }

    // generate/recover the encryption key
    memset(gcm_crypto, 0, sizeof(gcm_crypto_t));
    if (xfer_ctx->xfer_op == UCAFS_STORE) {
	sgx_read_rand((uint8_t *)gcm_crypto, sizeof(gcm_crypto_t)); 
    } else {
	memcpy(gcm_crypto, xfer_ctx->chunk, sizeof(gcm_crypto_t));

        enclave_crypto_ekey((crypto_ekey_t *)ekey, context->sealing_key, UC_DECRYPT);
    }

    // copy the IV
    memcpy(&context->_iv, &gcm_crypto->iv, sizeof(gcm_iv_t));

    memset(&context->_iv, 0, sizeof(gcm_crypto_t));
    memset(ekey, 0, sizeof(gcm_ekey_t));

    /* 3 - Setup the gcm context */
    gcm_ctx = &context->gcm_ctx;
    mbedtls_gcm_init(gcm_ctx);
    mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES, (uint8_t *)ekey, CONFIG_GCM_KEYBITS);
    mbedtls_gcm_starts(gcm_ctx, mode, (uint8_t *)&context->_iv,
                       sizeof(gcm_iv_t), NULL, 0);

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

    context->xfer_op = xfer_ctx->xfer_op;
    error = E_SUCCESS;
out:
    return error;
}

int
ecall_xfer_crypto(xfer_context_t * xfer_ctx)
{
    int error = E_ERROR_ERROR, nbytes;
    enclave_context_t * context;
    mbedtls_gcm_context * gcm_ctx;

    context = (enclave_context_t *)seqptrmap_get(xfer_context_map,
                                                 xfer_ctx->enclave_crypto_id);
    if (context == NULL) {
        return -1;
    }

    // the gcm context
    gcm_ctx = &context->gcm_ctx;

    uint8_t * p_input = context->input_buffer,
	    * p_data = xfer_ctx->buffer;

    int bytes_left = xfer_ctx->valid_buflen;
    while (bytes_left > 0) {
	nbytes = MIN(bytes_left, CONFIG_CRYPTO_BUFLEN);

	memcpy(p_input, p_data, nbytes);

	//mbedtls_gcm_update(gcm_ctx, nbytes, p_input, p_data);

	memcpy(p_data, p_input, nbytes);
	bytes_left -= nbytes;
	p_data += nbytes;
    }

    return 0;
}

int
ecall_xfer_finish(xfer_context_t * xfer_ctx)
{
    int error = 0, nbytes;
    gcm_tag_t tag;
    gcm_crypto_t * gcm_crypto;
    gcm_ekey_t * ekey;
    enclave_context_t * context;
    mbedtls_gcm_context * gcm_ctx;
    uc_filebox_t * filebox;

    context = (enclave_context_t *)seqptrmap_get(xfer_context_map,
                                                 xfer_ctx->enclave_crypto_id);
    if (context == NULL) {
        return -1;
    }

    filebox = xfer_ctx->filebox;
    gcm_crypto = &context->gcm_crypto;
    ekey = &gcm_crypto->ekey;
    gcm_ctx = &context->gcm_ctx;

    mbedtls_gcm_finish(gcm_ctx, (uint8_t *)&tag, sizeof(gcm_tag_t));
    mbedtls_gcm_free(gcm_ctx);

    if (context->xfer_op == UCAFS_STORE) {
        // copy the tag information
	memcpy(&gcm_crypto->tag, &tag, sizeof(gcm_tag_t));

        enclave_crypto_ekey((crypto_ekey_t *)ekey, context->sealing_key, UC_ENCRYPT);
	memcpy(xfer_ctx->chunk, gcm_crypto, sizeof(gcm_crypto_t));
    } else {
	error = memcmp(&tag, &gcm_crypto->tag, sizeof(gcm_tag_t));
    }

    seqptrmap_delete(xfer_context_map, xfer_ctx->enclave_crypto_id);
    free_enclave_context(context);

    xfer_ctx->enclave_crypto_id = -1;

    return error;
}
