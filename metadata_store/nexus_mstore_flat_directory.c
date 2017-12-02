/**
 * File provides a sample implementation of a NeXUS backend using flat
 * directories
 *
 * @author Judicael <jbriand@cs.pitt.edu>
 * @created Friday, Dec 1st 2017
 */

#include "nexus_mstore_internal.h"

struct nexus_metadata *
flatdir_read_metadata(struct nexus_dentry * dentry, struct path_builder * path)
{
    struct nexus_metadata * metadata = NULL;

    char *    fpath  = strndup(dentry->volume->metadata_dirpath, PATH_MAX);
    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    int ret = -1;

    // since everything is suppose to be in a flat directory, just use the
    // uuid of the dentry to read from the root metadata directory
    fpath = filepath_from_uuid(fpath, &dentry->uuid);
    ret   = read_file(fpath, &buffer, &buflen);
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

    metadata->fpath = fpath;
    metadata->is_root_dirnode = (dentry->parent == NULL);
    metadata->buffer = buffer;
    metadata->timestamp = clock();
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

struct metadata_operations flatdir_metadata_ops = {
    .read = flatdir_read_metadata,
    .write = flatdir_write_metadata
};
