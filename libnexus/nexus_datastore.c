/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>

#include <nexus_datastore.h>

#include <nexus_hashtable.h>
#include <nexus_util.h>
#include <nexus_log.h>

static struct nexus_hashtable * datastore_table = NULL;

/*
 * This is a place holder to ensure that the _nexus_datastores section gets created by gcc
 */
static struct {} null_datastore  __attribute__((__used__))                    \
__attribute__((used, __section__ ("_nexus_datastores"),			    \
                   aligned(sizeof(uintptr_t))));



static uint32_t
datastore_hash_fn(uintptr_t key)
{
    char * name = (char *)key;
    return nexus_hash_buffer((uint8_t *)name, strlen(name));
}


static int
datastore_eq_fn(uintptr_t key_1,
		uintptr_t key_2)
{
    char * name_1 = (char *)key_1;
    char * name_2 = (char *)key_2;
    
    return (strcasecmp(name_1, name_2) == 0);
}



int
nexus_datastores_init()
{
    extern struct nexus_datastore_impl  * __start__nexus_datastores[];
    extern struct nexus_datastore_impl  * __stop__nexus_datastores[];
    struct nexus_datastore_impl        ** tmp_datastore = __start__nexus_datastores;

    int i = 0;

    log_debug("Initializing Nexus Datastores\n");
    
    datastore_table = nexus_create_htable(0, datastore_hash_fn, datastore_eq_fn);


    if (datastore_table == NULL) {
	log_error("Could not allocate datastore table\n");
	return -1;
    }
    

    while (tmp_datastore != __stop__nexus_datastores) {
	log_debug("Registering Datastore (%s)\n", (*tmp_datastore)->name);


	if (nexus_htable_search(datastore_table, (uintptr_t)((*tmp_datastore)->name))) {
	    log_error("Datastore (%s) is already registered\n", (*tmp_datastore)->name);
	    return -1;
	}


	if (nexus_htable_insert(datastore_table, (uintptr_t)((*tmp_datastore)->name), (uintptr_t)(*tmp_datastore)) == 0) {
	    log_error("Could not register datastore (%s)\n", (*tmp_datastore)->name);
	    return -1;
	}
	
	tmp_datastore = &(__start__nexus_datastores[++i]);
    }
    
    
    return 0;
}


struct nexus_datastore *
nexus_datastore_create(char             * name,
		       nexus_json_obj_t   cfg)
{
    struct nexus_datastore      * datastore = NULL;
    struct nexus_datastore_impl * impl      = NULL;

    impl = nexus_htable_search(datastore_table, (uintptr_t)name);

    if (impl == NULL) {
	log_error("Could not find datastore implementation for (%s)\n", name);
	return NULL;
    }

    datastore = calloc(sizeof(struct nexus_datastore), 1);

    if (datastore == NULL) {
	log_error("Could not allocate nexus_datastore\n");
	return NULL;
    }

        
    log_debug("initializing datastore (%s)\n", name);

    datastore->impl      = impl;
    datastore->priv_data = datastore->impl->create(cfg);

    if (datastore->priv_data == NULL) {
	log_error("Error initializing datastore (%s)\n", name);
	nexus_free(datastore);
	return NULL;
    }

    return datastore;
}


struct nexus_datastore *
nexus_datastore_open(char             * name,
		     nexus_json_obj_t   cfg)
{
    struct nexus_datastore      * datastore = NULL;
    struct nexus_datastore_impl * impl      = NULL;

    impl = nexus_htable_search(datastore_table, (uintptr_t)name);

    if (impl == NULL) {
	log_error("Could not find datastore implementation for (%s)\n", name);
	return NULL;
    }

    datastore = calloc(sizeof(struct nexus_datastore), 1);

    if (datastore == NULL) {
	log_error("Could not allocate nexus_datastore\n");
	return NULL;
    }

        
    log_debug("initializing datastore (%s)\n", name);

    datastore->impl      = impl;
    datastore->priv_data = datastore->impl->open(cfg);

    if (datastore->priv_data == NULL) {
	log_error("Error initializing datastore (%s)\n", name);
	nexus_free(datastore);
	return NULL;
    }

    return datastore;
}


int
nexus_datastore_close(struct nexus_datastore * datastore)
{
    log_debug("Shutting down nexus datastore (%s)\n", datastore->impl->name);

    return -1;
}
