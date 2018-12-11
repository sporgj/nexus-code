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

#include "rootkey-exchange.h"

#include "sgx_backend_common.h"
#include "buffer_manager.h"
#include "key_buffer.h"
// #include "fs.h"
#include "io.h"


// For every run of NeXUS, there will be a unique instance
extern struct nxs_instance * global_nxs_instance;


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


// main.c

int
nxs_create_enclave(const char * enclave_path, sgx_enclave_id_t * enclave_id);

int
nxs_destroy_enclave(sgx_enclave_id_t enclave_id);


// manages the instance
int
nxs_create_instance(char * enclave_path, char * instance_fpath);

int
nxs_load_instance(char * instance_fpath);


int
sgx_backend_create_volume(struct nexus_volume * volume, void * priv_data);

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data);


int
sgx_backend_fs_create(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      nexus_dirent_type_t    type,
                      nexus_file_mode_t      mode,
                      struct nexus_uuid    * uuid,
                      void                 * priv_data);

int
sgx_backend_fs_remove(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      struct nexus_uuid    * uuid,
                      bool                 * should_remove,
                      void                 * priv_data);

int
sgx_backend_fs_lookup(struct nexus_volume    * volume,
                      char                   * dirpath,
                      char                   * plain_name,
                      struct nexus_fs_lookup * lookup_info,
                      void                   * priv_data);
int
sgx_backend_fs_setattr(struct nexus_volume   * volume,
                       char                  * path,
                       struct nexus_fs_attr  * attrs,
                       nexus_fs_attr_flags_t   flags,
                       void                  * priv_data);
int
sgx_backend_fs_stat(struct nexus_volume * volume,
                    char                * dirpath,
                    nexus_stat_flags_t    stat_flags,
                    struct nexus_stat   * nexus_stat,
                    void                * priv_data);

int
sgx_backend_fs_filldir(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * nexus_name,
                       char                ** plain_name,
                       void                 * priv_data);

int
sgx_backend_fs_readdir(struct nexus_volume  * volume,
                       char                 * dirpath,
                       struct nexus_dirent  * dirent_buffer_array,
                       size_t                 dirent_buffer_count,
                       size_t                 offset,
                       size_t               * result_count,
                       size_t               * directory_size,
                       void                 * priv_data);
int
sgx_backend_fs_symlink(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * link_name,
                       char                 * target_path,
                       struct nexus_uuid    * uuid,
                       void                 * priv_data);

int
sgx_backend_fs_readlink(struct nexus_volume  * volume,
                        char                 * dirpath,
                        char                 * linkname,
                        char                ** target,
                        void                 * priv_data);

int
sgx_backend_fs_hardlink(struct nexus_volume  * volume,
                        char                 * link_dirpath,
                        char                 * link_name,
                        char                 * target_dirpath,
                        char                 * target_name,
                        struct nexus_uuid    * uuid,
                        void                 * priv_data);

int
sgx_backend_fs_rename(struct nexus_volume  * volume,
                      char                 * from_dirpath,
                      char                 * oldname,
                      char                 * to_dirpath,
                      char                 * newname,
                      struct nexus_uuid    * entry_uuid,
                      struct nexus_uuid    * overriden_uuid,
                      bool                 * should_remove,
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
sgx_backend_user_list(struct nexus_volume * volume, void * priv_data);


int
sgx_backend_user_add(struct nexus_volume * volume,
                     char                * username,
                     char                * pubkey_str,
                     void                * priv_data);

int
sgx_backend_user_delname(struct nexus_volume * volume, char * username, void * priv_data);


int
sgx_backend_user_delkey(struct nexus_volume * volume, char * pubkey, void * priv_data);

int
sgx_backend_user_findname(struct nexus_volume * volume, char * username, void * priv_data);

int
sgx_backend_user_findkey(struct nexus_volume * volume, char * pubkey, void * priv_data);








int
uuid_equal_func(uintptr_t key1, uintptr_t key2);

uint32_t
uuid_hash_func(uintptr_t key);
