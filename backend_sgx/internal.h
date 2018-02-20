#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nexus_backend.h>
#include <nexus_key.h>
#include <nexus_log.h>
#include <nexus_uuid.h>
#include <nexus_util.h>
#include <nexus_volume.h>
#include <nexus_user_data.h>

#include <sgx_urts.h>

#include "nexus_enclave_u.h"

#include "sgx_backend_common.h"
#include "buffer_manager.h"

struct sgx_backend {
    sgx_enclave_id_t enclave_id;

    struct buffer_manager * buf_manager;

    struct nexus_volume * volume;
};


int
sgx_backend_create_volume(struct nexus_volume * volume, void * priv_data);

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data);


int
sgx_backend_fs_create(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      nexus_dirent_type_t    type,
                      char                ** nexus_name,
                      void                 * priv_data);

int
sgx_backend_fs_remove(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      char                ** nexus_name,
                      void                 * priv_data);

int
sgx_backend_fs_lookup(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      char                ** nexus_name,
                      void                 * priv_data);

int
sgx_backend_fs_filldir(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * nexus_name,
                       char                ** plain_name,
                       void                 * priv_data);


void
key_buffer_init(struct nexus_key_buffer * key_buffer);

int
key_buffer_put(struct nexus_key_buffer * key_buffer, struct nexus_key * key);

void
key_buffer_free(struct nexus_key_buffer * key_buffer);

int
key_buffer_derive(struct nexus_key_buffer * key_buffer, struct nexus_key * key);
