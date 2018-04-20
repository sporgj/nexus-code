/**
 * Copyright (c) 2018, Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#include <stdbool.h>

#include <nexus_datastore.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_file_handle.h>
#include <nexus_util.h>
#include <nexus_types.h>


#define LEVEL2_DIRNAME_LEN  2

struct twolevel_datastore {
    char * root_path;
};

static char *
__generic_full_path(struct twolevel_datastore * datastore, struct nexus_uuid * uuid, bool makedir)
{
    char * filename  = NULL;
    char * dirpath   = NULL;
    char * full_path = NULL;

    int ret = 0;

    filename = nexus_uuid_to_alt64(uuid);

    if (filename == NULL) {
        log_error("Could not generate base64 string\n");
        return NULL;
    }

    dirpath = strndup(filename, LEVEL2_DIRNAME_LEN);


    if (makedir) {
        char * dir_fullpath = NULL;

        ret = asprintf(&dir_fullpath, "%s/%s", datastore->root_path, dirpath);

        if (ret == -1) {
            log_error("asprintf failed\n");
            goto out_err;
        }

        ret = mkdir(dir_fullpath, 0770);

        if ((ret == -1) && (errno != EEXIST)) {
            log_error("could not create directory (%s)\n", dir_fullpath);

            nexus_free(dir_fullpath);
            goto out_err;
        }

        nexus_free(dir_fullpath);
    }

    ret = asprintf(&full_path, "%s/%s/%s", datastore->root_path, dirpath, filename);

    nexus_free(dirpath);

    nexus_free(filename);

    if (ret == -1) {
        log_error("asprintf failed\n");
        return NULL;
    }

    return full_path;

out_err:
    nexus_free(dirpath);
    nexus_free(filename);

    return NULL;
}

static char *
__make_full_path(struct twolevel_datastore * datastore, struct nexus_uuid * uuid)
{
    return __generic_full_path(datastore, uuid, true);
}

static char *
__get_full_path(struct twolevel_datastore * datastore, struct nexus_uuid * uuid)
{
    return __generic_full_path(datastore, uuid, false);
}

static void *
twolevel_create(nexus_json_obj_t cfg)
{
    struct twolevel_datastore * datastore = NULL;

    char * root_path = NULL;
    int    ret       = 0;

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

    datastore = nexus_malloc(sizeof(struct twolevel_datastore));

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
twolevel_delete(nexus_json_obj_t cfg)
{
    char * root_path = NULL;

    int ret = 0;

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
twolevel_open(nexus_json_obj_t cfg)
{
    struct twolevel_datastore * datastore = NULL;

    char * volume_path = NULL;

    char * root_path = NULL;
    int    ret       = 0;

    ret = nexus_json_get_string(cfg, "root_path", &root_path);

    if (ret == -1) {
        log_error("Invalid FLAT datastore config. Missing root_path\n");
        return NULL;
    }

    if (strlen(root_path) >= PATH_MAX) {
        log_error("Root path is too long\n");
        return NULL;
    }

    datastore = nexus_malloc(sizeof(struct twolevel_datastore));

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
twolevel_close(void * priv_data)
{
    struct twolevel_datastore * datastore = (struct twolevel_datastore *)priv_data;

    nexus_free(datastore->root_path);
    nexus_free(datastore);

    return 0;
}

static int
twolevel_get_uuid(struct nexus_uuid  * uuid,
                  char               * path,
                  uint8_t           ** buf,
                  uint32_t           * size,
                  void               * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;
    char                      * filename  = NULL;

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

struct nexus_file_handle *
twolevel_fopen(struct nexus_uuid * uuid, char * path, nexus_io_flags_t flags, void * priv_data)
{
    struct twolevel_datastore * datastore   = priv_data;

    struct nexus_file_handle  * file_handle = NULL;

    char                      * filepath    = NULL;


    filepath = __make_full_path(datastore, uuid);

    if (filepath == NULL) {
        log_error("could not get filepath\n");
        return NULL;
    }


    file_handle = nexus_file_handle_open(filepath, flags);

    nexus_free(filepath);

    if (file_handle == NULL) {
        log_error("nexus_open_file_handle FAILED\n");
        return NULL;
    }

    return file_handle;
}

int
twolevel_fread(struct nexus_file_handle  * file_handle,
                uint8_t                 ** buf,
                size_t                   * size,
                void                     * priv_data)
{
    return nexus_file_handle_read(file_handle, buf, size);
}

int
twolevel_fwrite(struct nexus_file_handle * file_handle,
                uint8_t                  * buf,
                size_t                     size,
                void                     * priv_data)
{
    return nexus_file_handle_write(file_handle, buf, size);
}

void
twolevel_fclose(struct nexus_file_handle * file_handle, void * priv_data)
{
    nexus_file_handle_close(file_handle);
}



static int
__put_uuid_failsafe(char * filepath, uint8_t * buf, uint32_t size)
{
    char * lastslash = NULL;
    char * dirpath   = NULL;

    int    ret       = -1;

    // XXX: turn this into nexus library function
    lastslash = strrchr(filepath, '/');
    dirpath = strndup(filepath, (int)(lastslash - filepath));

    ret = mkdir(dirpath, 0770);

    if ((ret == -1) && (errno != EEXIST)) {
        log_error("could not create directory (%s)\n", dirpath);

        nexus_free(dirpath);
        return -1;
    }

    nexus_free(dirpath);

    return nexus_write_raw_file(filepath, buf, size);
}



static int
twolevel_put_uuid(struct nexus_uuid * uuid,
                  char              * path,
                  uint8_t           * buf,
                  uint32_t            size,
                  void              * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;

    char * filename = NULL;

    int ret = -1;

    filename = __get_full_path(datastore, uuid);

    if (filename == NULL) {
        log_error("Could not get filename\n");
        return -1;
    }


    ret = __put_uuid_failsafe(filename, buf, size);

    if (ret != 0) {
        log_error("could not add file (%s)", filename);

        nexus_free(filename);
        return -1;
    }

    return 0;
}

static int
twolevel_update_uuid(struct nexus_uuid * uuid,
                     char              * path,
                     uint8_t           * buf,
                     uint32_t            size,
                     void              * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;

    char * filename = NULL;

    int ret = -1;


    filename = __get_full_path(datastore, uuid);

    if (filename == NULL) {
        log_error("Could not get filename\n");
        return -1;
    }


    ret = nexus_write_raw_file(filename, buf, size);

    if (ret != 0) {
        log_error("Could not write file (%s)", filename);

        nexus_free(filename);
        return -1;
    }

    return 0;
}

static int
twolevel_stat_uuid(struct nexus_uuid * uuid,
                   char              * path,
                   struct nexus_stat * stat,
                   void              * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;

    char                      * filename  =  __get_full_path(datastore, uuid);

    int                         ret       = -1;



    if (filename == NULL) {
        log_error("Could not get filename\n");
        return -1;
    }

    ret = nexus_stat_raw_file(filename, stat);

    nexus_free(filename);

    return ret;
}


static int
twolevel_new_uuid(struct nexus_uuid * uuid, char * path, void * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;
    char *                      filepath  = NULL;

    int ret = -1;

    filepath = __make_full_path(datastore, uuid);

    if (filepath == NULL) {
        log_error("could not get filepath\n");
        return -1;
    }

    ret = nexus_touch_raw_file(filepath);

    nexus_free(filepath);

    return ret;
}

static int
twolevel_del_uuid(struct nexus_uuid * uuid, char * path, void * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;
    char *                      filename  = NULL;

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
twolevel_hardlink_uuid(struct nexus_uuid * link_uuid,
                       char              * link_path,
                       struct nexus_uuid * target_uuid,
                       char              * target_path,
                       void              * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;

    char * link_fullpath   = NULL;
    char * target_fullpath = NULL;

    int ret = -1;

    link_fullpath   = __get_full_path(datastore, link_uuid);
    target_fullpath = __make_full_path(datastore, target_uuid);

    if ((link_fullpath == NULL) || (target_fullpath == NULL)) {
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
twolevel_rename_uuid(struct nexus_uuid * from_uuid,
                     char              * from_path,
                     struct nexus_uuid * to_uuid,
                     char              * to_path,
                     void              * priv_data)
{
    struct twolevel_datastore * datastore = priv_data;

    char * from_fullpath = NULL;
    char * to_fullpath   = NULL;

    int ret = -1;

    from_fullpath = __get_full_path(datastore, from_uuid);
    to_fullpath   = __make_full_path(datastore, to_uuid);

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



static struct nexus_datastore_impl twolevel_datastore = {
    .name          = "TWOLEVEL",

    .create        = twolevel_create,
    .delete        = twolevel_delete,

    .open          = twolevel_open,
    .close         = twolevel_close,

    .get_uuid      = twolevel_get_uuid,
    .put_uuid      = twolevel_put_uuid, // TODO remove
    .update_uuid   = twolevel_update_uuid, // TODO remove

    .stat_uuid     = twolevel_stat_uuid,
    .new_uuid      = twolevel_new_uuid,
    .del_uuid      = twolevel_del_uuid,

    .fopen         = twolevel_fopen,
    .fread         = twolevel_fread,
    .fwrite        = twolevel_fwrite,
    .fclose        = twolevel_fclose,

    .hardlink_uuid = twolevel_hardlink_uuid,
    .rename_uuid   = twolevel_rename_uuid
};


nexus_register_datastore(twolevel_datastore);
