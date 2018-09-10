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
#include <nexus_heap.h>

#include <nexus_probes.h>

#include <sgx_urts.h>

#include "nexus_enclave_u.h"

#include "sgx_backend_common.h"
#include "buffer_manager.h"
#include "key_buffer.h"
// #include "fs.h"
#include "io.h"


struct sgx_backend {
    sgx_enclave_id_t              enclave_id;

    size_t                        volume_chunk_size;

    struct buffer_manager       * buf_manager;


    struct nexus_heap             heap_manager;

    uint8_t                     * mmap_ptr;

    size_t                        mmap_len;


    struct fs_manager           * fs_manager;


    struct nexus_volume         * volume;

    char                        * enclave_path;
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
int
sgx_backend_fs_symlink(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * link_name,
                       char                 * target_path,
                       char                ** nexus_name,
                       void                 * priv_data);

int
sgx_backend_fs_hardlink(struct nexus_volume  * volume,
                        char                 * link_dirpath,
                        char                 * link_name,
                        char                 * target_dirpath,
                        char                 * target_name,
                        char                ** nexus_name,
                        void                 * priv_data);

int
sgx_backend_fs_rename(struct nexus_volume  * volume,
                      char                 * from_dirpath,
                      char                 * oldname,
                      char                 * to_dirpath,
                      char                 * newname,
                      char                ** old_nexusname,
                      char                ** new_nexusname,
                      void                 * priv_data);

int
sgx_backend_fs_encrypt(struct nexus_volume * volume,
                       char                * filepath,
                       uint8_t             * in_buf,
                       uint8_t             * out_buf,
                       size_t                offset,
                       size_t                size,
                       size_t                filesize,
                       void                * priv_data);

int
sgx_backend_fs_decrypt(struct nexus_volume * volume,
                       char                * filepath,
                       uint8_t             * in_buf,
                       uint8_t             * out_buf,
                       size_t                offset,
                       size_t                size,
                       size_t                filesize,
                       void                * priv_data);



int
uuid_equal_func(uintptr_t key1, uintptr_t key2);

uint32_t
uuid_hash_func(uintptr_t key);
