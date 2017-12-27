#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nexus_backend.h>
#include <nexus_log.h>
#include <nexus_uuid.h>
#include <nexus_util.h>
#include <nexus_volume.h>

#include "nexus_enclave_u.h"

#include "sgx_backend_common.h"

struct sgx_backend_info {
    sgx_enclave_id_t enclave_id;
    
    struct nexus_volume * volume; 
};
