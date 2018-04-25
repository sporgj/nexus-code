#include "enclave_internal.h"

struct __crypto_context_buf {
    uint8_t key[GCM128_KEY_SIZE];
    uint8_t  iv[GCM128_IV_SIZE];
    uint8_t mac[NEXUS_MAC_SIZE];
} __attribute__((packed));


size_t
nexus_crypto_ctx_bufsize(void)
{
    return sizeof(struct __crypto_context_buf);
}

int
nexus_crypto_ctx_serialize(struct nexus_crypto_ctx * crypto_ctx, uint8_t * buffer, size_t buflen)
{
    struct __crypto_context_buf * buf = (struct __crypto_context_buf *)buffer;

    uint8_t * ret_ptr                 = NULL;


    ret_ptr = nexus_key_to_buf(&(crypto_ctx->key), buf->key, GCM128_KEY_SIZE);

    if (ret_ptr == NULL) {
        log_error("could not serialize key to buffer\n");
        return -1;
    }


    ret_ptr = nexus_key_to_buf(&(crypto_ctx->iv), buf->iv, GCM128_KEY_SIZE);

    if (ret_ptr == NULL) {
        log_error("could not serialize iv to buffer\n");
        return -1;
    }

    nexus_mac_to_buf(&(crypto_ctx->mac), buf->mac);

    return 0;
}

int
nexus_crypto_ctx_parse(struct nexus_crypto_ctx * crypto_ctx, uint8_t * buffer, size_t buflen)
{
    struct __crypto_context_buf * buf = (struct __crypto_context_buf *)buffer;

    int                           ret = -1;

    ret = __nexus_key_from_buf(&(crypto_ctx->key), NEXUS_RAW_128_KEY, buf->key, GCM128_KEY_SIZE);

    if (ret != 0) {
        log_error("could not parse key from buffer\n");
        return -1;
    }

    ret = __nexus_key_from_buf(&(crypto_ctx->iv), NEXUS_RAW_128_KEY, buf->iv, GCM128_KEY_SIZE);

    if (ret != 0) {
        log_error("could not parse IV from buffer\n");
        return -1;
    }


    ret = __nexus_mac_from_buf(&(crypto_ctx->mac), buf->mac);

    if (ret != 0) {
        log_error("could not get mac from buf\n");
        return -1;
    }

    return 0;
}

void
nexus_crypto_ctx_init(struct nexus_crypto_ctx * crypto_ctx)
{
    memset(crypto_ctx, 0, sizeof(struct nexus_crypto_ctx));
}

void
nexus_crypto_ctx_generate(struct nexus_crypto_ctx * crypto_ctx)
{
    // free the previously allocated buffer
    nexus_crypto_ctx_free(crypto_ctx);

    nexus_generate_key(&(crypto_ctx->key), NEXUS_RAW_128_KEY);
    nexus_generate_key(&(crypto_ctx->iv),  NEXUS_RAW_128_KEY);
    nexus_mac_zeroize(&(crypto_ctx->mac));
}

void
nexus_crypto_ctx_free(struct nexus_crypto_ctx * crypto_ctx)
{
    if (crypto_ctx->key.key) {
        nexus_free_key(&(crypto_ctx->key));
    }

    if (crypto_ctx->iv.key) {
        nexus_free_key(&(crypto_ctx->iv));
    }
}

void
nexus_crypto_ctx_copy(struct nexus_crypto_ctx * src_crypto_ctx,
                      struct nexus_crypto_ctx * dst_crypto_ctx)
{
    memcpy(dst_crypto_ctx, src_crypto_ctx, sizeof(struct nexus_crypto_ctx));
}
