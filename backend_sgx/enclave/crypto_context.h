#pragma once

#include <nexus_key.h>

struct nexus_crypto_ctx {
    struct nexus_key key;
    struct nexus_key iv; // let's leverage the IV as a 128-bit key
    struct nexus_mac mac;
} __attribute__((packed));


void
nexus_crypto_ctx_init(struct nexus_crypto_ctx * crypto_ctx);

void
nexus_crypto_ctx_free(struct nexus_crypto_ctx * crypto_ctx);

void
nexus_crypto_ctx_generate(struct nexus_crypto_ctx * crypto_ctx);
