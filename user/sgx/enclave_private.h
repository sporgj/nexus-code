#pragma once

#include "enclave_t.h"

/* data protection levels for enclave variable */
#define __TOPSECRET__ // resides in enclave, not erased
#define __SECRET // resides in enclave, gets erased
#define _CONFIDENTIAL // copyh in and out with care

#define E_CRYPTO_BUFFER_LEN 256
