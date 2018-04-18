/**
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
#include <limits.h>


#include <nexus_datastore.h>
#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_locked_file.h>
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
    
    ret = mkdir(root_path, 0770);

    if (ret == -1) {
	if (errno == EEXIST) {
	    printf(". WARNING: directory (%s) already exists\n", root_path);
	} else {
	    log_error("Could not create FLAT datastore directory (%s)\n", root_path);
	    printf("%s\n", strerror(errno));
	    return NULL;
	}
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


static int
flat_delete(nexus_json_obj_t cfg)
{
    char * root_path = NULL;

    int    ret = 0;

    ret = nexus_json_get_string(cfg, "root_path", &root_path);

    if (ret == -1) {
	log_error("Invalid FLAT datastore config. Missing root_path\n");
	return -1;
    }

    
    ret = nexus_delete_path(root_path);

    if (ret == -1) {
	log_error("Could not delete path (%s)\n", root_path);
	return -1;
    }
    
    return 0;
}

static void *
flat_open(nexus_json_obj_t cfg)
{
    struct flat_datastore * datastore = NULL;

    char * volume_path = NULL;

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

    // the volume path is the cwd
    volume_path = get_current_dir_name();

    asprintf(&datastore->root_path, "%s/%s", volume_path, root_path);

    nexus_free(volume_path);

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
flat_put_uuid(struct nexus_uuid * uuid,
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
flat_update_uuid(struct nexus_uuid * uuid,
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

static int
flat_hardlink_uuid(struct nexus_uuid * link_uuid,
                   char              * from_path,
                   struct nexus_uuid * target_uuid,
                   char              * target_path,
                   void              * priv_data)
{
    struct flat_datastore * datastore = priv_data;

    char * link_fullpath   = NULL;
    char * target_fullpath = NULL;

    int ret = -1;

    link_fullpath   = __get_full_path(datastore, link_uuid);
    target_fullpath = __get_full_path(datastore, target_uuid);

    if (link_fullpath == NULL || target_fullpath == NULL) {
	log_error("could not derive link/target path\n");
	goto err_out;
    }

    ret = link(target_fullpath, link_fullpath);

    if (ret != 0) {
	log_error("hardlink '%s' -> '%s' FAILED\n", target_fullpath, link_fullpath);
	perror("error: ");
	goto err_out;
    }

    ret = 0;
err_out:
    if (link_fullpath) {
	nexus_free(link_fullpath);
    }

    if (target_fullpath) {
	nexus_free(target_fullpath);
    }

    return ret;
}


int
flat_rename_uuid(struct nexus_uuid * from_uuid,
                 char              * from_path,
                 struct nexus_uuid * to_uuid,
                 char              * to_path,
                 void              * priv_data)
{
    struct flat_datastore * datastore = priv_data;

    char * from_fullpath = NULL;
    char * to_fullpath   = NULL;

    int ret = -1;

    from_fullpath = __get_full_path(datastore, from_uuid);
    to_fullpath   = __get_full_path(datastore, to_uuid);

    if ((from_fullpath == NULL) || (to_fullpath == NULL)) {
        log_error("error deriving paths (from=%s, to=%s)\n", from_fullpath, to_fullpath);
        goto err_out;
    }

    ret = rename(from_fullpath, to_fullpath);

    if (ret != 0) {
        log_error("renaming '%s' -> '%s' FAILED\n", from_fullpath, to_fullpath);
        goto err_out;
    }

    ret = 0;
err_out:
    if (from_fullpath) {
        nexus_free(from_fullpath);
    }

    if (to_fullpath) {
        nexus_free(to_fullpath);
    }

    return ret;
}


struct nexus_locked_file *
flat_open_locked(struct nexus_uuid  * uuid,
                 char               * path,
                 uint8_t           ** buf,
                 uint32_t           * size,
                 void               * priv_data)
{
    struct flat_datastore    * datastore   = priv_data;

    struct nexus_locked_file * locked_file = NULL;

    char                     * filepath    = NULL;


    filepath = __get_full_path(datastore, uuid);

    if (filepath == NULL) {
        log_error("could not get filepath\n");
        return NULL;
    }


    locked_file = nexus_open_locked_file(filepath, buf, (size_t *)size);

    nexus_free(filepath);

    if (locked_file == NULL) {
        log_error("nexus_open_locked_file FAILED\n");
	return NULL;
    }

    return locked_file;
}

int
flat_write_locked(struct nexus_locked_file * locked_file,
                  uint8_t                  * buf,
                  uint32_t                   size,
                  void                     * priv_data)
{
    return nexus_write_locked_file(locked_file, buf, size);
}

void
flat_close_locked(struct nexus_locked_file * locked_file, void * priv_data)
{
    nexus_close_locked_file(locked_file);
}


static struct nexus_datastore_impl flat_datastore = {
    .name        = "FLAT",

    .create      = flat_create,
    .delete      = flat_delete,

    .open        = flat_open,
    .close       = flat_close,

    .get_uuid    = flat_get_uuid,
    .put_uuid    = flat_put_uuid,
    .update_uuid = flat_update_uuid,
    .del_uuid    = flat_del_uuid,

    .open_uuid   = flat_open_locked,
    .write_uuid  = flat_write_locked,
    .close_uuid  = flat_close_locked,

    .hardlink_uuid = flat_hardlink_uuid,
    .rename_uuid   = flat_rename_uuid
};


nexus_register_datastore(flat_datastore);
