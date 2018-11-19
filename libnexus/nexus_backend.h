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

    // int (*user_add)(struct nexus_uuid * vol_uuid,
    //                 struct nexus_key  * user_pub_key,
    //                 char              * user_name);

    // int (*user_del)(struct nexus_uuid * vol_uuid, struct nexus_key * user_name);

    /**
     * Creates a new file
     */
    int (*fs_touch)(struct nexus_volume  * volume,
                    char                 * dirpath,
                    char                 * plain_name,
                    nexus_dirent_type_t    type,
                    struct nexus_uuid    * uuid,
                    void                 * priv_data);

    int (*fs_remove)(struct nexus_volume  * volume,
                     char                 * dirpath,
                     char                 * plain_name,
                     struct nexus_uuid    * uuid,
                     void                 * priv_data);

    int (*fs_lookup)(struct nexus_volume    * volume,
                     char                   * dirpath,
                     char                   * plain_name,
                     struct nexus_fs_lookup * lookup_info,
                     void                   * priv_data);

    int   (*fs_stat)(struct nexus_volume  * volume,
                     char                 * path,
                     struct nexus_stat    * nexus_stat,
                     void                 * priv_data);

    int (*fs_getattr)(struct nexus_volume   * volume,
                      char                  * path,
                      struct nexus_fs_attr  * attrs,
                      void                  * priv_data);

    int (*fs_setattr)(struct nexus_volume   * volume,
                      char                  * path,
                      struct nexus_fs_attr  * attrs,
                      nexus_fs_attr_flags_t   flags,
                      void                  * priv_data);

    int (*fs_filldir)(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * nexus_name,
                      char                ** plain_name,
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

    int (*fs_rename)(struct nexus_volume  * volume,
                     char                 * from_dirpath,
                     char                 * oldname,
                     char                 * to_dirpath,
                     char                 * newname,
                     struct nexus_uuid    * entry_uuid,
                     struct nexus_uuid    * overriden_uuid,
                     void                 * priv_data);

    int (*fs_encrypt)(struct nexus_volume * volume,
                      char                * path,
                      uint8_t             * in_buf,
                      uint8_t             * out_buf,
                      size_t                offset,
                      size_t                size,
                      size_t                filesize,
                      void                * priv_data);

    int (*fs_decrypt)(struct nexus_volume * volume,
                      char                * path,
                      uint8_t             * in_buf,
                      uint8_t             * out_buf,
                      size_t                offset,
                      size_t                size,
                      size_t                filesize,
                      void                * priv_data);

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


#define nexus_register_backend(backend)							\
    static struct nexus_backend_impl * _nexus_backend					\
    __attribute__((used))								\
	 __attribute__((unused, __section__("_nexus_backends"),				\
			aligned(sizeof(void *))))					\
	 = &backend;




int
nexus_backend_init();

int
nexus_backend_exit();







#if 0

// authenticates with the backend

extern int
nexus_backend_authenticate(struct nexus_supernode * supernode,
			   struct nexus_vol_key   * vol_key,
			   struct nexus_pub_key   * pub_key,
			   struct nexus_prv_key   * prv_key);







// volume management
extern int
backend_volume_create(struct uuid *      supernode_uuid,
                      struct uuid *      root_uuid,
		      char *       publickey_fpath,
                      struct supernode * supernode_out,
                      struct dirnode *   dirnode_out,
                      struct volumekey * volume_out);

// dirnode management
extern int
backend_dirnode_new(struct uuid *     dirnode_uuid,
                    struct uuid *     root_uuid,
                    struct dirnode ** p_dirnode);

extern int
backend_dirnode_add(struct dirnode *    parent_dirnode,
                    struct uuid *       uuid,
                    const char *        fname,
                    nexus_fs_obj_type_t type);

extern int
backend_dirnode_find_by_uuid(struct dirnode *      dirnode,
                             struct uuid *         uuid,
                             char **               p_fname,
                             nexus_fs_obj_type_t * p_type);

extern int
backend_dirnode_find_by_name(struct dirnode *      dirnode,
                             char *                fname,
                             struct uuid *         uuid,
                             nexus_fs_obj_type_t * p_type);

extern int
backend_dirnode_remove(struct dirnode *      dirnode,
                       char *                fname,
                       struct uuid *         uuid,
                       nexus_fs_obj_type_t * p_type);

extern int
backend_dirnode_serialize(struct dirnode *  dirnode,
                          struct dirnode ** p_sealed_dirnode);


#endif
