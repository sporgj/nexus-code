#include "enclave_internal.h"

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
