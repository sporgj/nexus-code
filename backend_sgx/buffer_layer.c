#include "internal.h"

void
nexus_cryptobuf_free(struct crypto_buffer * crypto_buffer)
{
    nexus_free(crypto_buffer->untrusted_addr);
    nexus_free(crypto_buffer);
}

void
nexus_rawbuf_free(struct raw_buffer * raw_buffer)
{
    nexus_free(raw_buffer->untrusted_addr);
    nexus_free(raw_buffer);
}

void
nexus_sealedbuf_free(struct sealed_buffer * sealed_buffer)
{
    nexus_free(sealed_buffer);
}
