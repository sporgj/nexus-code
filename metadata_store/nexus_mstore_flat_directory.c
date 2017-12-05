/**
 * File provides a sample implementation of a NeXUS backend using flat
 * directories
 *
 * @author Judicael <jbriand@cs.pitt.edu>
 * @created Friday, Dec 1st 2017
 */

#include <unistd.h>

#include "nexus_mstore_internal.h"

struct nexus_metadata *
flatdir_read_metadata(struct nexus_dentry * dentry,
                      struct path_builder * path,
                      size_t *              p_size)
{
    struct nexus_metadata * metadata = NULL;

    char *    fpath  = strndup(dentry->volume->metadata_dirpath, PATH_MAX);
    uint8_t * buffer = NULL;

    int ret = -1;

    // since everything is suppose to be in a flat directory, just use the
    // uuid of the dentry to read from the root metadata directory
    fpath = filepath_from_uuid(fpath, &dentry->uuid);
    ret   = read_file(fpath, &buffer, p_size);
    if (ret != 0) {
        nexus_free(fpath);
        log_error("reading metadata file FAILED (%s)", fpath);
        return NULL;
    }

    metadata
        = (struct nexus_metadata *)calloc(1, sizeof(struct nexus_metadata));

    if (!metadata) {
	log_error("allocation error");
	goto out;
    }

    metadata->volume = dentry->volume;
    metadata->fpath = fpath;
    metadata->is_root_dirnode = (dentry->parent == NULL);
    metadata->buffer = buffer;
    metadata->timestamp = clock();

    metadata->private_data = &flatdir_metadata_ops; 
out:
    if (ret) {
	nexus_free(fpath);

	if (buffer) {
	    nexus_free(buffer);
	}
    }

    return metadata;
}

int
flatdir_write_metadata(struct nexus_metadata * metadata, size_t size)
{
    if (write_file(metadata->fpath, metadata->buffer, size)) {
        log_error("writing metadata file FAILED (%s)", metadata->fpath);
        return -1;
    }

    metadata->timestamp = clock();

    return 0;
}

int
flatdir_create_metadata(struct nexus_metadata * parent_metadata,
                        struct uuid *           uuid,
                        nexus_fs_obj_type_t     type)
{
    char * fpath = NULL;
    FILE * fd    = NULL;

    // create an empty file in the root directory
    fpath = strndup(parent_metadata->volume->metadata_dirpath, PATH_MAX);
    fpath = filepath_from_uuid(fpath, uuid);

    fd = fopen(fpath, "wb");
    nexus_free(fpath);

    if (fd == NULL) {
	log_error("creating file (%s) FAILED", fpath);
	return -1;
    }

    fclose(fd);

    return 0;
}

int
flatdir_delete_metadata(struct nexus_metadata * parent_metadata,
                        struct uuid *           uuid)
{
    char * fpath = NULL;
    int    ret   = -1;

    // create an empty file in the root directory
    fpath = strndup(parent_metadata->volume->metadata_dirpath, PATH_MAX);
    fpath = filepath_from_uuid(fpath, uuid);

    ret = unlink(fpath);
    if (ret != 0) {
	// XXX: Not sure if it's necessary to return a FAIL flag here
	log_error("unlink (%s) FAILED", fpath);
    }

    nexus_free(fpath);

    return 0;
}

struct metadata_operations flatdir_metadata_ops
    = {.read   = flatdir_read_metadata,
       .write  = flatdir_write_metadata,
       .create = flatdir_create_metadata,
       .delete = flatdir_delete_metadata };
