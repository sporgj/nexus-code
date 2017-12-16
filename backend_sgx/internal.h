#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <nexus_backend.h>
#include <nexus_key.h>
#include <nexus_log.h>
#include <nexus_uuid.h>
#include <nexus_util.h>
#include <nexus_types.h>

#include "nexus_enclave_u.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

extern sgx_enclave_id_t global_enclave_id;
