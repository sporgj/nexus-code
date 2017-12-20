/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>

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
nexus_backend_launch(char * name, nexus_json_obj_t * backend_cfg)
{
    struct nexus_backend      * backend = NULL;
    struct nexus_backend_impl * impl    = NULL;

    int ret = 0;
    
    impl = nexus_htable_search(backend_table, (uintptr_t)name);

    if (impl == NULL) {
	log_error("Could not find backend implementation for (%s)\n", name);
	return NULL;
    }

    backend = calloc(sizeof(struct nexus_backend), 1);

    if (backend == NULL) {
	log_error("Could not allocate nexus_backend\n");
	return NULL;
    }


    log_debug("initializing backend (%s)\n", name);
    
    ret = impl->init();

    if (ret != 0) {
	log_error("Error initializing backend (%s)\n", name);
	nexus_free(backend);
	return NULL;
    }

    backend->impl = impl;

    return backend;
}


// TODO
int
nexus_backend_create_volume(struct nexus_backend * backend,
			    struct nexus_volume  * volume)
{
    

    
    return -1;
}

void
nexus_backend_shutdown(struct nexus_backend * backend)
{
    log_debug("Shutting down nexus backend (%s)\n", backend->impl->name);


}