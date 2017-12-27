#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

#include "nexus_enclave_t.h"

#include "crypto.h"
#include "supernode.h"
#include "volume_usertable.h"
#include "dirnode.h"
#include "metadata.h"

#include "nexus_trusted/nexus_uuid.h"

#define ocall_debug(str) \
    ocall_print("enclave> " str "\n")


extern sgx_key_128bit_t global_enclave_sealing_key;

// pointer to the backend info. Used in ocalls;
void * global_backend_ext;
