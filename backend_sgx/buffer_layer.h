#pragma once
#include "sgx_backend_common.h"


void
nexus_cryptobuf_free(struct crypto_buffer * crypto_buffer);

void
nexus_rawbuf_free(struct raw_buffer * raw_buffer);

void
nexus_sealedbuf_free(struct sealed_buffer * sealed_buffer);
