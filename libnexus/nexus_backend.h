/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#pragma once

#include <nexus.h>

#include <nexus_key.h>
#include <nexus_uuid.h>
#include <nexus_json.h>

#include <nexus_fs.h>

struct nexus_backend_impl;
struct nexus_volume;



struct nexus_backend {

    struct nexus_backend_impl * impl;

    void * priv_data;
};



struct nexus_backend *
nexus_backend_launch(char * name, nexus_json_obj_t backend_cfg);

void nexus_backend_shutdown(struct nexus_backend * backend);



int
nexus_backend_init_volume(struct nexus_volume * volume);

int
nexus_backend_open_volume(struct nexus_volume * volume);



int
nexus_backend_user_list(struct nexus_volume * volume);

int
nexus_backend_user_add(struct nexus_volume * volume, char * username, char * pubkey_str);

int
nexus_backend_user_delname(struct nexus_volume * volume, char * username);

int
nexus_backend_user_delkey(struct nexus_volume * volume, char * pubkey);

int
nexus_backend_user_findname(struct nexus_volume * volume, char * username);

int
nexus_backend_user_findkey(struct nexus_volume * volume, char * pubkey);



struct nexus_backend_impl {
    char * name;

    void * (*init)(nexus_json_obj_t backend_cfg);
    int    (*deinit)();

    int (*volume_init)(struct nexus_volume * volume, void * priv_data);

    int (*volume_open)(struct nexus_volume * volume, void * priv_data);

    int (*volume_close)(struct nexus_uuid * uuid);


    /**
     * Creates a new file
     */
    int (*fs_create)(struct nexus_volume  * volume,
                     char                 * dirpath,
                     char                 * plain_name,
                     nexus_dirent_type_t    type,
                     struct nexus_uuid    * uuid,
                     void                 * priv_data);

    int (*fs_remove)(struct nexus_volume    * volume,
                     char                   * dirpath,
                     char                   * plain_name,
                     struct nexus_fs_lookup * lookup_info,
                     bool                   * should_remove,
                     void                   * priv_data);

    int (*fs_lookup)(struct nexus_volume    * volume,
                     char                   * dirpath,
                     char                   * plain_name,
                     struct nexus_fs_lookup * lookup_info,
                     void                   * priv_data);

    int   (*fs_stat)(struct nexus_volume  * volume,
                     char                 * path,
                     nexus_stat_flags_t     stat_flags,
                     struct nexus_stat    * nexus_stat,
                     void                 * priv_data);

    int (*fs_readdir)(struct nexus_volume  * volume,
                      char                 * dirpath,
                      struct nexus_dirent  * dirent_buffer_array,
                      size_t                 dirent_buffer_count,
                      size_t                 offset,
                      size_t               * result_count,
                      size_t               * directory_size,
                      void                 * priv_data);

    int (*fs_symlink)(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * link_name,
                      char                 * target_path,
                      struct nexus_uuid    * uuid,
                      void                 * priv_data);

    int (*fs_readlink)(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * linkname,
                       char                ** target,
                       void                 * priv_data);

    int (*fs_hardlink)(struct nexus_volume  * volume,
                       char                 * link_dirpath,
                       char                 * link_name,
                       char                 * target_dirpath,
                       char                 * target_name,
                       struct nexus_uuid    * uuid,
                       void                 * priv_data);

    int (*fs_rename)(struct nexus_volume     * volume,
                     char                    * from_dirpath,
                     char                    * oldname,
                     char                    * to_dirpath,
                     char                    * newname,
                     struct nexus_uuid       * entry_uuid,
                     struct nexus_fs_lookup  * overriden_entry,
                     bool                    * should_remove,
                     void                    * priv_data);


    int (*fs_truncate)(struct nexus_volume   * volume,
                       char                  * path,
                       size_t                  size,
                       struct nexus_stat     * stat,
                       void                  * priv_data);


    struct nexus_file_crypto *
    (*fs_file_encrypt_start)(struct nexus_volume * volume, char * filepath, size_t filesize, void * priv_data);

    struct nexus_file_crypto *
    (*fs_file_decrypt_start)(struct nexus_volume * volume, char * filepath, void * priv_data);

    int (*fs_file_crypto_seek)(struct nexus_file_crypto * file_crypto, size_t offset);

    int (*fs_file_crypto_encrypt)(struct nexus_file_crypto * file_crypto,
                                  const uint8_t            * plaintext_input,
                                  uint8_t                  * encrypted_output,
                                  size_t                     size,
                                  size_t                   * processed_bytes);

    int (*fs_file_crypto_decrypt)(struct nexus_file_crypto * file_crypto,
                                  uint8_t                  * decrypted_output,
                                  size_t                     size,
                                  size_t                   * processed_bytes);

    int (*fs_file_crypto_finish)(struct nexus_file_crypto * file_crypto);


    int (*user_list)(struct nexus_volume * volume, void * priv_data);

    int (*user_add)(struct nexus_volume * volume,
                    char *                username,
                    char *                pubkey_str,
                    void *                priv_data);

    int (*user_delname)(struct nexus_volume * volume, char * username, void * priv_data);

    int (*user_delkey)(struct nexus_volume * volume, char * pubkey, void * priv_data);

    int (*user_findname)(struct nexus_volume * volume, char * username, void * priv_data);

    int (*user_findkey)(struct nexus_volume * volume, char * pubkey, void * priv_data);
};


#define nexus_register_backend(backend)                                                            \
    static struct nexus_backend_impl * _nexus_backend __attribute__((used))                        \
        __attribute__((unused, __section__("_nexus_backends"), aligned(sizeof(void *))))           \
        = &backend;

int
nexus_backend_init();

int
nexus_backend_exit();
