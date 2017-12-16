/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <nexus_datastore.h>
#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_util.h>
#include <nexus_types.h>


struct flat_datastore {
    char * root_path;
};

static char *
__get_full_path(struct flat_datastore * datastore,
		struct nexus_uuid     * uuid)
{
    char * filename  = NULL;
    char * full_path = NULL;

    int ret = 0;
    
    filename = nexus_uuid_to_alt64(uuid);
	
    if (filename == NULL) {
	log_error("Could not generate alt64 string\n");
	return NULL;
    }

    ret = asprintf(&full_path, "%s/%s", datastore->root_path, filename);

    nexus_free(filename);

    if (ret == -1) {
	return NULL;
    }

    return full_path;
}


static void *
flat_create(nexus_json_obj_t cfg)
{
    struct flat_datastore * datastore = NULL;

    char * root_path = NULL;
    int    ret = 0;

    ret = nexus_json_get_string(cfg, "root_path", &root_path);

    if (ret == -1) {
	log_error("Invalid FLAT datastore config. Missing root_path\n");
	return NULL;
    }

    if (strlen(root_path) >= PATH_MAX) {
	log_error("Root path is too long\n");
	return NULL;
    }
    
    ret = mkdir(root_path, 0660);

    if (ret == -1) {
	log_error("Could not create FLAT datastore directory (%s)\n", root_path);
	return NULL;
    }
    
    datastore = calloc(1, sizeof(struct flat_datastore));

    if (datastore == NULL) {
	log_error("Could not allocate datastore state\n");
	goto err;
    }

    datastore->root_path = strndup(root_path, PATH_MAX);

    return datastore;

 err:

    rmdir(root_path);
    
    return NULL;
}


static void *
flat_open(nexus_json_obj_t cfg)
{
    struct flat_datastore * datastore = NULL;

    char * root_path = NULL;
    int    ret = 0;

    ret = nexus_json_get_string(cfg, "root_path", &root_path);

    if (ret == -1) {
	log_error("Invalid FLAT datastore config. Missing root_path\n");
	return NULL;
    }

    if (strlen(root_path) >= PATH_MAX) {
	log_error("Root path is too long\n");
	return NULL;
    }
    
    datastore = calloc(1, sizeof(struct flat_datastore));

    if (datastore == NULL) {
	log_error("Could not allocate datastore state\n");
	return NULL;
    }
    
    datastore->root_path = strndup(root_path, PATH_MAX);

    return datastore;
}


static int
flat_close(void * priv_data)
{
    struct flat_datastore * datastore = (struct flat_datastore *)priv_data;

    nexus_free(datastore->root_path);
    nexus_free(datastore);

    return 0;
}

static int
flat_get_uuid(struct nexus_uuid  * uuid,
	      char               * path,
	      uint8_t           ** buf,
	      uint32_t           * size,
	      void               * priv_data)
{
    struct flat_datastore * datastore = priv_data;
    char                  * filename  = NULL;

    int ret = -1;

    filename = __get_full_path(datastore, uuid);

    if (filename == NULL) {
	log_error("Could not get filename\n");
	return -1;
    }
    
    ret = nexus_read_raw_file(filename, buf, (size_t *)size);

    if (ret != 0) {
        log_error("Could not read file (%s)\n", filename);
	goto err;
    }


    nexus_free(filename);
    return 0;

 err:
    nexus_free(filename);
    return -1;
}

static int
flat_set_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      uint8_t           * buf,
	      uint32_t            size,
	      void              * priv_data)
{
    struct flat_datastore * datastore = priv_data;
    char                  * filename  = NULL;
    
    int ret = -1;

    filename = __get_full_path(datastore, uuid);

    if (filename == NULL) {
	log_error("Could not get filename\n");
	goto err;
    }    

    
    // stat the file, make sure it exists
    ret = access(filename, W_OK);

    if (ret == -1) {
	if (errno == ENOENT) {
	    log_error("Could not set UUID: File (%s) does not exist\n", filename);
	} else {
	    log_error("Could not set UUID: Access error (errno=%d)\n", errno);
	}

	goto err;
    }
    
    ret = nexus_write_raw_file(filename, buf, size);

    if (ret != 0) {
        log_error("Could not write file (%s)", filename);
	goto err;
    }


    nexus_free(filename);
    return 0;

 err:
    nexus_free(filename);
    return -1;

}

static int
flat_add_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      uint8_t           * buf,
	      uint32_t            size,
	      void              * priv_data)
{
    struct flat_datastore * datastore = priv_data;
    char                  * filename  = NULL;

    int ret = -1;

    filename = __get_full_path(datastore, uuid);


    if (filename == NULL) {
	log_error("Could not get filename\n");
	goto err;
    }    
    
    // stat the file, make sure it doesn't exist
    ret = access(filename, W_OK);

    if ( !( (ret == -1) &&
	    (errno == ENOENT) ) ) {

	log_error("Tried to add a file that already exists\n");
	goto err;
    }

    ret = nexus_write_raw_file(filename, buf, size);
    
    if (ret != 0) {
        log_error("Could not add file (%s)", filename);
	goto err;
    }


    nexus_free(filename);
    return 0;

 err:

    nexus_free(filename);
    return -1;
}
    
static int
flat_del_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      void              * priv_data)
{
    struct flat_datastore * datastore = priv_data;
    char                  * filename  = NULL;

    int ret = -1;

    filename = __get_full_path(datastore, uuid);

    if (filename == NULL) {
	log_error("Could not get filename\n");
	goto err;
    }
    
    ret = nexus_delete_raw_file(filename);

    if (ret != 0) {
        log_error("Could not delete file (%s)", filename);
	goto err;
    }


    nexus_free(filename);
    return 0;

 err:
    nexus_free(filename);
    return -1;
    
}





static struct nexus_datastore_impl flat_datastore = {
    .name     = "FLAT",

    .create   = flat_create,
    
    .open     = flat_open,
    .close    = flat_close,

    .get_uuid = flat_get_uuid,
    .set_uuid = flat_set_uuid,
    .add_uuid = flat_add_uuid,
    .del_uuid = flat_del_uuid
};


nexus_register_datastore(flat_datastore);
