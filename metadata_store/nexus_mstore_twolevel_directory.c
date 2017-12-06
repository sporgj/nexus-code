/**
 * TRies to store directories in the git-style storage fashion
 *
 * @author Judicael <jbriand@cs.pitt.edu>
 * @created Friday, Dec 1st 2017
 */

#include <unistd.h>
#include <sys/stat.h>

#include "nexus_mstore_internal.h"

#define FILENAME_PREFIX_LEN 2

static char *
twolevel_filepath(struct nexus_volume * volume,
                  struct uuid *         uuid,
                  bool                  is_root_dirnode,
                  char **               p_dirname)
{

    char * filepath = strndup(volume->metadata_dirpath, PATH_MAX);
    char * filename = uuid_to_string(uuid);

    if (!is_root_dirnode) {
        char * prefix = strndup(filename, FILENAME_PREFIX_LEN);
        filepath = filepath_from_name(filepath, prefix);
        nexus_free(prefix);

        if (p_dirname) {
            *p_dirname = strdup(filepath);
        }
    }

    filepath = filepath_from_name(filepath, filename);

    nexus_free(filename);

    return filepath;
}

struct nexus_metadata *
twolevel_read_metadata(struct nexus_dentry * dentry,
                       struct path_builder * path,
                       size_t *              p_size)
{
    struct nexus_metadata * metadata = NULL;

    char *    filepath = NULL;
    uint8_t * buffer   = NULL;

    int ret = -1;

    filepath = twolevel_filepath(
        dentry->volume, &dentry->uuid, (dentry->parent == NULL), NULL);

    ret = read_file(filepath, &buffer, p_size);

    if (ret != 0) {
        log_error("reading metadata file (%s) FAILED", filepath);
        goto out;
    }

    metadata = alloc_metadata(dentry, filepath, buffer);
    if (metadata == NULL) {
        log_error("alloc_metadata failed");
        goto out;
    }

    metadata->private_data = &twolevel_metadata_ops;
out:
    if (ret) {

        if (metadata) {
            nexus_free(metadata);
        }
    }

    return metadata;
}

int
twolevel_write_metadata(struct nexus_metadata * metadata, size_t size)
{
    if (write_file(metadata->fpath, metadata->buffer, size)) {
        log_error("writing metadata file FAILED (%s)", metadata->fpath);
        return -1;
    }

    return 0;
}

int
twolevel_create_metadata(struct nexus_metadata * parent_metadata,
                         struct uuid *           uuid,
                         nexus_fs_obj_type_t     type)
{
    char * dirpath = NULL;
    char * filepath = twolevel_filepath(parent_metadata->volume, uuid, false, &dirpath);

    // create the directory
    int ret = mkdir(dirpath, S_IRWXU);
    nexus_free(dirpath);

    if (ret != 0) {
        nexus_free(filepath);
        log_error("mkdir (%s) FAILED", dirpath);
        return -1;
    }

    FILE * fd = fopen(filepath, "wb");
    if (fd == NULL) {
        log_error("creating file (%s) FAILED", filepath);
        nexus_free(filepath);
        return -1;
    }

    fclose(fd);
    nexus_free(filepath);

    return 0;
}

int
twolevel_delete_metadata(struct nexus_metadata * parent_metadata,
                         struct uuid *           uuid)
{
    char * fpath = NULL;
    int    ret   = -1;

    // create an empty file in the root directory
    fpath = twolevel_filepath(parent_metadata->volume, uuid, false, NULL);

    ret = unlink(fpath);
    if (ret != 0) {
        // XXX: Not sure if it's necessary to return a FAIL flag here
        log_error("unlink (%s) FAILED", fpath);
    }

    nexus_free(fpath);

    return 0;
}

struct metadata_operations twolevel_metadata_ops = {
    .read   = twolevel_read_metadata,
    .write  = twolevel_write_metadata,
    .create = twolevel_create_metadata,
    .delete = twolevel_delete_metadata
};
