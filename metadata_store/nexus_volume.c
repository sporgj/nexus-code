#include "nexus_mstore_internal.h"

struct nexus_volume *
alloc_volume(const char * metadata_dirpath, const char * datafolder_dirpath)
{
    struct nexus_volume * volume      = NULL;
    struct nexus_dentry * root_dentry = NULL;

    volume = (struct nexus_volume *)calloc(1, sizeof(struct nexus_volume *));
    if (volume == NULL) {
        log_error("allocation error");
        return NULL;
    }

    root_dentry = (struct nexus_dentry *)calloc(1, sizeof(struct nexus_dentry));
    if (root_dentry == NULL) {
        nexus_free(volume);
        log_error("allocation error");
        return NULL;
    }

    volume->root_dentry        = root_dentry;
    volume->metadata_dirpath   = strndup(metadata_dirpath, PATH_MAX);
    volume->datafolder_dirpath = strndup(datafolder_dirpath, PATH_MAX);

    root_dentry->volume = volume;

    return volume;
}

void
free_volume(struct nexus_volume * volume)
{
    if (volume) {
        if (volume->metadata_dirpath) {
            nexus_free(volume->metadata_dirpath);
        }

        if (volume->datafolder_dirpath) {
            nexus_free(volume->datafolder_dirpath);
        }

	if (volume->supernode) {
	    nexus_free(volume->supernode);
	}

	if (volume->volumekey) {
	    nexus_free(volume->volumekey);
	}

        nexus_free(volume);
    }
}
