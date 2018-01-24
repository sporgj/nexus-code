#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <assert.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

#include "nexus_enclave_t.h"

#include "buffer_layer.h"
#include "crypto_buffer.h"
#include "sealed_buffer.h"
#include "raw_buffer.h"

#include "volumekey.h"
#include "crypto.h"
#include "supernode.h"
#include "usertable.h"
#include "dirnode.h"
#include "metadata.h"

#include "nexus_log.h"
#include "nexus_mac.h"
#include "nexus_hash.h"
#include "nexus_uuid.h"
#include "nexus_util.h"
#include "nexus_key.h"

#define ocall_debug(str) \
    ocall_print("enclave> " str "\n")


extern struct nexus_key * global_volumekey;

// pointer to the backend info. Used in ocalls;
void * global_backend_ext;
