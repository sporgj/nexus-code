#pragma once

#include <sgx_urts.h>

#include "enclave_u.h"
#include "uc_types.h"

#define ENCLAVE_FILENAME "sgx/enclave.signed.so"

extern sgx_enclave_id_t global_eid;
