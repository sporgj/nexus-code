#pragma once

#include "libnexus_trusted/nexus_key.h"
#include "libnexus_trusted/nexus_mac.h"

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

void
nexus_crypto_ctx_copy(struct nexus_crypto_ctx * src_crypto_ctx,
                      struct nexus_crypto_ctx * dst_crypto_ctx);


size_t
nexus_crypto_ctx_bufsize(void);

int
nexus_crypto_ctx_serialize(struct nexus_crypto_ctx * crypto_ctx, uint8_t * buffer, size_t buflen);

int
nexus_crypto_ctx_parse(struct nexus_crypto_ctx * crypto_ctx, uint8_t * buffer, size_t buflen);

