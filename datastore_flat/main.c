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

#include <unistd.h>

#include <nexus_datastore.h>
#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_util.h>
#include <nexus_types.h>


struct flat_datastore_info {
    char * volume_path;
    nexus_datastore_mode_t mode;
};


static char *
flat_datastore_make_filepath(struct flat_datastore_info * datastore_info,
                             struct nexus_uuid          * uuid)
{
    char * filepath = NULL;

    filepath = strndup(datastore_info->volume_path, PATH_MAX);
    filepath = nexus_filepath_from_uuid(filepath, uuid);

    return filepath;
}



static void *
flat_open(char * volume_path, nexus_json_obj_t cfg, nexus_datastore_mode_t mode)
{
    struct flat_datastore_info * datastore_info = NULL;

    datastore_info = calloc(1, sizeof(struct flat_datastore_info));
    if (datastore_info == NULL) {
	log_error("allocation error");
	return NULL;
    }

    datastore_info->mode = mode;
    datastore_info->volume_path = strndup(volume_path, PATH_MAX);

    return datastore_info;
}


static int
flat_close(void * priv_data)
{
    struct flat_datastore_info * datastore_info
        = (struct flat_datastore_info *)priv_data;

    nexus_free(datastore_info->volume_path);
    nexus_free(datastore_info);

    return 0;
}

static int
flat_get_uuid(struct nexus_uuid  * uuid,
	      char               * path,
	      uint8_t           ** p_buf,
	      uint32_t           * p_size,
	      void               * priv_data)
{
    struct flat_datastore_info * datastore_info = NULL;

    char * filepath = NULL;

    int ret = -1;


    datastore_info = (struct flat_datastore_info *)priv_data;

    filepath = flat_datastore_make_filepath(datastore_info, uuid);

    ret = nexus_read_raw_file(filepath, p_buf, (size_t *)p_size);
    if (ret != 0) {
        log_error("reading (%s) FAILED", filepath);
    }


    nexus_free(filepath);

    return ret;
}

static int
flat_set_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      uint8_t           * buf,
	      uint32_t            size,
	      void              * priv_data)
{
    struct flat_datastore_info * datastore_info = NULL;

    char * filepath = NULL;

    int ret = -1;


    datastore_info = (struct flat_datastore_info *)priv_data;

    filepath = flat_datastore_make_filepath(datastore_info, uuid);

    ret = nexus_write_raw_file(filepath, buf, size);
    if (ret != 0) {
        log_error("writing (%s) FAILED", filepath);
    }


    nexus_free(filepath);

    return ret;
}

static int
flat_add_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      void              * priv_data)
{
    struct flat_datastore_info * datastore_info = NULL;

    char * filepath = NULL;

    int ret = -1;


    datastore_info = (struct flat_datastore_info *)priv_data;

    filepath = flat_datastore_make_filepath(datastore_info, uuid);

    ret = nexus_create_raw_file(filepath);
    if (ret != 0) {
        log_error("creating (%s) FAILED", filepath);
    }


    nexus_free(filepath);

    return ret;
}
    
static int
flat_del_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      void              * priv_data)
{
    struct flat_datastore_info * datastore_info = NULL;

    char * filepath = NULL;

    int ret = -1;


    datastore_info = (struct flat_datastore_info *)priv_data;

    filepath = flat_datastore_make_filepath(datastore_info, uuid);

    ret = nexus_delete_raw_file(filepath);
    if (ret != 0) {
        log_error("removing (%s) FAILED", filepath);
    }


    nexus_free(filepath);

    return ret;
}





static struct nexus_datastore_impl flat_datastore = {
    .name     = "FLAT",
    .open     = flat_open,
    .close    = flat_close,

    .get_uuid = flat_get_uuid,
    .set_uuid = flat_set_uuid,
    .add_uuid = flat_add_uuid,
    .del_uuid = flat_del_uuid
};


nexus_register_datastore(flat_datastore);
