/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>

#include <nexus_volume.h>

#include <nexus_backend.h>

#include <nexus_hashtable.h>
#include <nexus_util.h>
#include <nexus_log.h>

static struct nexus_hashtable * backend_table = NULL;

/*
 * This is a place holder to ensure that the _nexus_backends section gets created by gcc
 */
static struct {} null_backend  __attribute__((__used__))                    \
__attribute__((used, __section__ ("_nexus_backends"),                  \
                   aligned(sizeof(uintptr_t))));



static uint32_t
backend_hash_fn(uintptr_t key)
{
    char * name = (char *)key;
    return nexus_hash_buffer((uint8_t *)name, strlen(name));
}


static int
backend_eq_fn(uintptr_t key_1,
	      uintptr_t key_2)
{
    char * name_1 = (char *)key_1;
    char * name_2 = (char *)key_2;
    
    return (strcasecmp(name_1, name_2) == 0);
}



int
nexus_backend_init()
{
    extern struct nexus_backend_impl  * __start__nexus_backends[];
    extern struct nexus_backend_impl  * __stop__nexus_backends[];
    struct nexus_backend_impl        ** tmp_backend = __start__nexus_backends;

    int i = 0;

    log_debug("Initializing Nexus Backends\n");
    
    backend_table = nexus_create_htable(0, backend_hash_fn, backend_eq_fn);


    if (backend_table == NULL) {
	log_error("Could not allocate backend table\n");
	return -1;
    }
    

    while (tmp_backend != __stop__nexus_backends) {
	log_debug("Registering Backend (%s)\n", (*tmp_backend)->name);


	if (nexus_htable_search(backend_table, (uintptr_t)((*tmp_backend)->name))) {
	    log_error("Backend (%s) is already registered\n", (*tmp_backend)->name);
	    return -1;
	}


	if (nexus_htable_insert(backend_table, (uintptr_t)((*tmp_backend)->name), (uintptr_t)(*tmp_backend)) == 0) {
	    log_error("Could not register backend (%s)\n", (*tmp_backend)->name);
	    return -1;
	}
	
	tmp_backend = &(__start__nexus_backends[++i]);
    }
    
    
    return 0;
}




struct nexus_backend *
nexus_backend_launch(char             * name,
		     nexus_json_obj_t   backend_cfg)
{
    struct nexus_backend      * backend = NULL;
    struct nexus_backend_impl * impl    = NULL;
   
    impl = nexus_htable_search(backend_table, (uintptr_t)name);

    if (impl == NULL) {
	log_error("Could not find backend implementation for (%s)\n", name);
	return NULL;
    }

    backend = nexus_malloc(sizeof(struct nexus_backend));

    log_debug("initializing backend (%s)\n", name);
    
    backend->impl      = impl;
    backend->priv_data = impl->init(backend_cfg);

    if (backend->priv_data == NULL) {
	log_error("backend_init FAILED (%s)\n", name);
	nexus_free(backend);
	return NULL;
    }

    return backend;
}


int
nexus_backend_init_volume(struct nexus_volume * volume)
{
    struct nexus_backend * backend = volume->backend;
    
    return backend->impl->volume_init(volume, backend->priv_data);
}


int
nexus_backend_open_volume(struct nexus_volume * volume)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->volume_open(volume, backend->priv_data);
}

void
nexus_backend_shutdown(struct nexus_backend * backend)
{
    log_debug("Shutting down nexus backend (%s)\n", backend->impl->name);


}


int
nexus_backend_fs_create(struct nexus_volume * volume,
			char                * path,
			nexus_dirent_type_t   type,
			struct nexus_stat   * stat)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->fs_create(volume, path, type, stat, backend->priv_data);
}




int
nexus_backend_fs_touch(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * plain_name,
                       nexus_dirent_type_t    type,
                       char                ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_touch == NULL) {
	log_error("fs_touch NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_touch(volume, dirpath, plain_name, type, nexus_name, backend->priv_data);
}

int
nexus_backend_fs_remove(struct nexus_volume * volume,
                        char                * dirpath,
                        char                * plain_name,
                        char               ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_remove == NULL) {
	log_error("fs_remove NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_remove(volume, dirpath, plain_name, nexus_name, backend->priv_data);
}

int
nexus_backend_fs_lookup(struct nexus_volume * volume,
                        char                * dirpath,
                        char                * plain_name,
                        char               ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_lookup == NULL) {
	log_error("fs_lookup NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_lookup(volume, dirpath, plain_name, nexus_name, backend->priv_data);
}

int
nexus_backend_fs_filldir(struct nexus_volume * volume,
                         char                * dirpath,
                         char                * nexus_name,
                         char               ** plain_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_filldir == NULL) {
	log_error("fs_filldir NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_filldir(volume, dirpath, nexus_name, plain_name, backend->priv_data);
}

int
nexus_backend_fs_symlink(struct nexus_volume * volume,
                         char                * dirpath,
                         char                * link_name,
                         char                * target_path,
                         char               ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_symlink == NULL) {
	log_error("fs_symlink NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_symlink(volume,
                                     dirpath,
                                     link_name,
                                     target_path,
                                     nexus_name,
                                     backend->priv_data);
}

int
nexus_backend_fs_hardlink(struct nexus_volume  * volume,
                          char                 * link_dirpath,
                          char                 * link_name,
                          char                 * target_dirpath,
                          char                 * target_name,
                          char                ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_symlink == NULL) {
	log_error("fs_symlink NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_hardlink(volume,
                                      link_dirpath,
                                      link_name,
                                      target_dirpath,
                                      target_name,
                                      nexus_name,
                                      backend->priv_data);
}

int
nexus_backend_fs_rename(struct nexus_volume  * volume,
                        char                 * from_dirpath,
                        char                 * oldname,
                        char                 * to_dirpath,
                        char                 * newname,
                        char                ** old_nexusname,
                        char                ** new_nexusname)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_rename == NULL) {
	log_error("fs_rename NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_rename(volume,
                                    from_dirpath,
                                    oldname,
                                    to_dirpath,
                                    newname,
                                    old_nexusname,
                                    new_nexusname,
                                    backend->priv_data);
}
