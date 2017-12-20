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



struct nexus_backend_impl;
struct nexus_volume;



struct nexus_backend {

    struct nexus_backend_impl * impl;

    void * private_data;
};



struct nexus_backend *
nexus_backend_launch(char * name, nexus_json_obj_t * backend_cfg);

void nexus_backend_shutdown(struct nexus_backend * backend);



int
nexus_backend_create_volume(struct nexus_backend  * backend,
			    struct nexus_volume   * volume);







struct nexus_backend_impl {
    char * name;

    int (*init)();
    int (*deinit)();

    void * (*create_volume)(struct nexus_volume * volume);
    void * (*open_volume)(struct nexus_volume * volume);

    int (*close_volume)(struct nexus_uuid * uuid);

    
    
    int (*add_user)(struct nexus_uuid * vol_uuid,
		    struct nexus_key  * user_pub_key,
		    char              * user_name);

    int (*del_user)(struct nexus_uuid * vol_uuid,
		    struct nexus_key  * user_name);


    int (*add_dir)(struct nexus_uuid * vol_uuid,
		   char              * name,
		   char              * path);
    
    int (*del_dir)();

    int (*read_dir)();
    
    int (*add_file)();
    int (*del_file)();

    int (*read_file)();
    int (*write_file)();

    int (*setacl)();
    
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