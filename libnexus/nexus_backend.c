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
nexus_backend_user_list(struct nexus_volume * volume)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->user_list(volume, backend->priv_data);
}

int
nexus_backend_user_add(struct nexus_volume * volume, char * username, char * pubkey_str)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->user_add(volume, username, pubkey_str, backend->priv_data);
}

int
nexus_backend_user_delname(struct nexus_volume * volume, char * username)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->user_delname(volume, username, backend->priv_data);
}

int
nexus_backend_user_delkey(struct nexus_volume * volume, char * pubkey)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->user_delkey(volume, pubkey, backend->priv_data);
}

int
nexus_backend_user_findname(struct nexus_volume * volume, char * username)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->user_findname(volume, username, backend->priv_data);
}

int
nexus_backend_user_findkey(struct nexus_volume * volume, char * pubkey)
{
    struct nexus_backend * backend = volume->backend;

    return backend->impl->user_findkey(volume, pubkey, backend->priv_data);
}
