#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nexus_backend.h>
#include <nexus_log.h>
#include <nexus_uuid.h>
#include <nexus_util.h>
#include <nexus_volume.h>
#include <nexus_user_data.h>

#include <sgx_urts.h>

#include "nexus_enclave_u.h"

#include "sgx_backend_common.h"

#include "buffer_layer.h"

struct sgx_backend_info {
    sgx_enclave_id_t enclave_id;
    
    struct nexus_volume * volume; 
};


int
sgx_backend_create_volume(struct nexus_volume * volume, void * priv_data);

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data);
