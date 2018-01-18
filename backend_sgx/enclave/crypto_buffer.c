#include "internal.h"



typedef enum {
    MAGIC_GCM_128 = 0x6e780001   // GCM 128 bits key
} crypto_buf_magic_t;


/* Crypto buffer serialized format */
/*
   uint32_t magic;   // to determine which algorithm to use
   uint32_t version; // Version of the data
   uint32_t size;    // size of the encrypted buffer

   crypto_ctx;       // Contains the sealed crypto information

   Data
*/

// this will be prepacked
struct crypto_buf_info {
    crypto_buf_magic_t magic;

    uint32_t version;

    uint32_t size; // size of the encrypted buffer
} __attribute__((packed));



struct nexus_crypto_buf {
    crypto_buf_magic_t magic;
    uint32_t           version;

    struct nexus_crypto_ctx crypto_ctx;

    // for managing the untrusted buffer
    struct nexus_uuid * buffer_uuid;
    uint8_t           * untrusted_addr;
    size_t              untrusted_size;

    uint8_t * trusted_addr;
    size_t    trusted_size;
};

// ---- GCM stuff ----
static const GCM128_KEY_SIZE = 16;
static const GCM128_IV_SIZE  = 16;

static int
__get_header_len(struct nexus_crypto_buf * crypto_buf)
{
    struct nexus_crypto_ctx * crypto_ctx = &crypto_buf->crypto_ctx;

    if (crypto_buf->magic == MAGIC_GCM_128) {
        return (GCM128_KEY_SIZE + GCM128_IV_SIZE + sizeof(struct nexus_mac));
    }

    log_error("Invalid magic value\n");
    return -1;
}

struct nexus_crypto_buf *
nexus_crypto_buf_new(size_t size)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    // by default we perform 128 bit GCM
    crypto_buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    // for now, let's default to GCM
    crypto_buf->magic = MAGIC_GCM_128;

    crypto_buf->trusted_addr = NULL;
    crypto_buf->trusted_size = size;

    return crypto_buf;
}

struct nexus_crypto_buf *
nexus_crypto_buf_create(void * untrusted_addr, size_t untrusted_size)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    crypto_buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    crypto_buf->buffer_uuid = buffer_layer_create(untrusted_addr, untrusted_size);
    if (crypto_buf->buffer_uuid == NULL) {
        nexus_free(crypto_buf);
        log_error("buffer_layer_create FAILED\n");
        return NULL;
    }

    crypto_buf->untrusted_addr = untrusted_addr;
    crypto_buf->untrusted_size = untrusted_size;

    return crypto_buf;
}

void
nexus_crypto_buf_free(struct nexus_crypto_buf * crypto_buf)
{
    assert(crypto_buf != NULL);

    if (crypto_buf->untrusted_addr) {
        ocall_free(crypto_buf->untrusted_addr);
    }

    if (crypto_buf->buffer_uuid) {
        buffer_layer_free(crypto_buf->buffer_uuid);
        nexus_free(crypto_buf->buffer_uuid);
    }

    // free the crypto context
    {
        struct nexus_crypto_ctx * crypto_context = &crypto_buf->crypto_ctx;

        if (crypto_context->key) {
            nexus_free_key(crypto_context->key);
            nexus_free(crypto_context->key);
        }

        if (crypto_context->iv != NULL) {
            nexus_free_key(crypto_context->iv);
            nexus_free(crypto_context->iv);
        }
    }

    nexus_free(crypto_buf);
}

static int
__parse_gcm128_context(struct nexus_crypto_buf  * crypto_buf,
                       uint8_t                  * untrusted_crypto_ctx_ptr)
{
    struct nexus_crypto_ctx * crypto_ctx = NULL;

    struct nexus_key * wrapped_key = NULL;
    struct nexus_key * iv          = NULL;
    struct nexus_mac * mac         = NULL;

    int ret = -1;


    crypto_ctx = &crypto_buf->crypto_ctx;
    mac = &crypto_ctx->mac;

    {
        uint8_t * in_buffer = NULL;
        size_t    in_buflen = 0;

        ret = -1;


        // adjust for the info section
        in_buflen = crypto_buf->untrusted_size - sizeof(struct crypto_buf_info);
        in_buffer = untrusted_crypto_ctx_ptr;


        wrapped_key = nexus_key_from_buf(NEXUS_WRAPPED_128_KEY, in_buffer, in_buflen);
        if (wrapped_key == NULL) {
            log_error("parsing crypto_ctx key FAILED\n");
            return -1;
        }

        in_buffer += GCM128_KEY_SIZE;
        in_buflen -= GCM128_KEY_SIZE;

        // IV
        iv = nexus_key_from_buf(NEXUS_RAW_128_KEY, in_buffer, in_buflen);
        if (iv == NULL) {
            log_error("parsing crypto_ctx key FAILED\n");
            goto out;
        }

        in_buffer += GCM128_IV_SIZE;
        in_buflen -= GCM128_IV_SIZE;

        // MAC
        nexus_mac_copy((struct nexus_mac *)in_buffer, mac);
    }

    crypto_ctx->key =  nexus_derive_key(NEXUS_RAW_128_KEY, wrapped_key);
    if (crypto_ctx->key == NULL) {
        ret = -1;
        log_error("__unwrap_gcm128_key FAILED\n");
        goto out;
    }

    crypto_ctx->iv  = iv;


    ret = 0;
out:
    if (wrapped_key) {
        nexus_free_key(wrapped_key);
        nexus_free(wrapped_key);
    }

    if (ret) {
        if (iv) {
            nexus_free_key(iv);
            nexus_free(iv);
        }
    }

    return ret;
}

static int
__parse_header(struct nexus_crypto_buf * crypto_buf, struct crypto_buf_info * buf_info)
{

    if (crypto_buf->untrusted_addr == NULL) {
        log_error("Tried to parse header of nexus_crypto_buf with no untrusted_addr\n");
        return -1;
    }

    memcpy(buf_info, crypto_buf->untrusted_addr, sizeof(struct crypto_buf_info));

    if (buf_info->magic == MAGIC_GCM_128) {

        return __parse_gcm128_context(crypto_buf,
                                      crypto_buf->untrusted_addr + sizeof(struct crypto_buf_info));
    }

    // parse the GCM context
    log_error("invalid magic value in crypto_buffer\n");
    return -1;
}

void *
nexus_crypto_buf_get(struct nexus_crypto_buf * crypto_buf,
                     struct nexus_mac        * mac)
{
    struct crypto_buf_info buf_info = { 0 };

    /* Check if there is an untrusted buf we need to decrypt. */
    size_t header_len = 0;

    int ret = -1;


    /* If its already there, just return it */
    if (crypto_buf->trusted_addr != NULL) {
        return crypto_buf->trusted_addr;
    }

    if (crypto_buf->untrusted_addr == NULL) {
        log_error("the crypto_buffer points to nothing\n");
        return NULL;
    }


    // parses and unwraps the buffer's crypto context
    ret = __parse_header(crypto_buf, &buf_info);
    if (ret) {
        log_error("parsing crypto_buf header FAILED\n");
        goto err;
    }


    crypto_buf->magic   = buf_info.magic;
    crypto_buf->version = buf_info.version;


    header_len = sizeof(struct crypto_buf_info) + __get_header_len(crypto_buf);


    /* Allocate trusted memory */
    crypto_buf->trusted_size = crypto_buf->untrusted_size - header_len;
    crypto_buf->trusted_addr = nexus_malloc(crypto_buf->trusted_size);

    /* Decrypt the buffer */
    {
        ret = crypto_gcm_decrypt(&crypto_buf->crypto_ctx,
                                 crypto_buf->trusted_size,
                                 crypto_buf->untrusted_addr + header_len,
                                 crypto_buf->trusted_addr,
                                 mac,
                                 (uint8_t *)&buf_info,
                                 sizeof(struct crypto_buf_info));

        if (ret) {
            log_error("crypto_gcm_decrypt() FAILED\n");
            goto err;
        }
    }


    return crypto_buf->trusted_addr;
err:
    nexus_free(crypto_buf->trusted_addr);

    return NULL;
}

static int
__serialize_gcm128_context(struct nexus_crypto_buf * crypto_buf,
                           uint8_t                 * untrusted_crypto_ctx_ptr)
{
    struct nexus_crypto_ctx * crypto_ctx  = NULL;

    struct nexus_key        * wrapped_key = NULL;

    int ret = -1;


    crypto_ctx = &crypto_buf->crypto_ctx;

    wrapped_key = nexus_derive_key(NEXUS_WRAPPED_128_KEY, crypto_ctx->key);
    if (wrapped_key == NULL) {
        log_error("could not wrap gcm128 key\n");
        return -1;
    }

    // serialize the crypto context
    {
        uint8_t * out_ptr    = NULL;
        uint8_t * out_buffer = NULL;
        size_t    out_buflen = 0;

        ret = -1;


        // adjust for the info section
        out_buflen = crypto_buf->untrusted_size - sizeof(struct crypto_buf_info);
        out_buffer = untrusted_crypto_ctx_ptr;

        // EKEY is sealed in the buffer
        out_ptr = nexus_key_to_buf(wrapped_key, out_buffer, out_buflen);
        if (out_ptr == NULL) {
            log_error("parsing crypto_ctx key FAILED\n");
            goto out;
        }

        out_buffer += GCM128_KEY_SIZE;
        out_buflen -= GCM128_KEY_SIZE;


        // IV
        out_ptr = nexus_key_to_buf(crypto_ctx->iv, out_buffer, out_buflen);
        if (out_ptr == NULL) {
            log_error("parsing crypto_ctx key FAILED\n");
            goto out;
        }

        out_buffer += GCM128_IV_SIZE;
	out_buflen -= GCM128_IV_SIZE;


        // MAC
        nexus_mac_copy(&crypto_ctx->mac, (struct nexus_mac *)out_buffer);
    }

    ret = 0;
out:
    nexus_free_key(wrapped_key);
    nexus_free(wrapped_key);

    return ret;
}

/**
 * Writes the crypto_context + buf_info into untrusted_addr
 */
static int
__serialize_header(struct nexus_crypto_buf * crypto_buf, struct crypto_buf_info * buf_info)
{
    /* Check magic against a version */
    if (crypto_buf->magic == MAGIC_GCM_128) {
        return __serialize_gcm128_context(crypto_buf,
                                          crypto_buf->untrusted_addr
                                             + sizeof(struct crypto_buf_info));
    }

    memcpy(crypto_buf->untrusted_addr, buf_info, sizeof(struct crypto_buf_info));

    log_error("Invalid magic value in crypto buffer\n");
    return -1;
}

int
nexus_crypto_buf_put(struct nexus_crypto_buf * crypto_buf,
                     uint8_t                 * trusted_buf,
                     struct nexus_mac        * mac)
{
    struct crypto_buf_info buf_info = { 0 };

    size_t header_len = 0;

    int ret = -1;


    header_len = __get_header_len(crypto_buf) + sizeof(struct crypto_buf_info);


    // if we have no space allocated...
    if (crypto_buf->untrusted_addr == NULL) {
        size_t total_size = header_len + crypto_buf->trusted_size;

        crypto_buf->buffer_uuid = buffer_layer_alloc(total_size, &crypto_buf->untrusted_addr);
        if (crypto_buf->buffer_uuid == NULL) {
            log_error("buffer_layer_alloc FAILED\n");
            return -1;
        }
    }


    crypto_buf->version += 1;


    // Set the crypto info. This is used as additional authentication
    // material when encrypting the trusted buffer
    buf_info.magic   = crypto_buf->magic;
    buf_info.version = crypto_buf->version;
    buf_info.size    = crypto_buf->untrusted_size;

    // encrypt the data
    crypto_buf->trusted_addr = trusted_buf;

    ret = crypto_gcm_encrypt(&crypto_buf->crypto_ctx,
                             crypto_buf->trusted_size,
                             crypto_buf->trusted_addr,
                             crypto_buf->untrusted_addr + header_len,
                             mac,
                             (uint8_t *)&buf_info,
                             sizeof(struct crypto_buf_info));


    // write the info + sealed(crypto_context) to the buffer
    ret = __serialize_header(crypto_buf, &buf_info);
    if (ret) {
        crypto_buf->version -= 1;
        log_error("serializing header FAILED\n");
        return -1;
    }

    return 0;
}
