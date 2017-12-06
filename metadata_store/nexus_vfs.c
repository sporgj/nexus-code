#include <sys/stat.h>
#include <unistd.h>

#include "nexus_mstore_internal.h"

static TAILQ_HEAD(volume_head, volume_entry) * mounted_volumes = NULL;

static int mounted_volumes_count = 0;

int
nexus_vfs_init()
{
    log_debug("Initializing the NeXUS virtual filesystem");

    mounted_volumes
        = (struct volume_head *)calloc(1, sizeof(struct volume_head));

    if (mounted_volumes == NULL) {
        log_error("allocation error");
        return -1;
    }

    TAILQ_INIT(mounted_volumes);

    return 0;
}

int
nexus_vfs_exit()
{
    struct volume_entry * curr = NULL;
    struct volume_entry * next = NULL;

    if (mounted_volumes) {
        TAILQ_FOREACH_SAFE(curr, mounted_volumes, next_item, next) {
            free_volume(curr->volume);
            nexus_free(curr);
        }

        nexus_free(mounted_volumes);
    }

    return 0;
}

int
vfs_add_volume(struct nexus_volume * volume)
{
    struct volume_entry * volume_entry
        = (struct volume_entry *)calloc(1, sizeof(struct volume_entry));

    if (volume_entry == NULL) {
        log_error("allocation error");
        return -1;
    }

    volume_entry->volume                 = volume;
    volume_entry->metadata_dirpath_len   = strlen(volume->metadata_dirpath);
    volume_entry->datafolder_dirpath_len = strlen(volume->datafolder_dirpath);

    TAILQ_INSERT_TAIL(mounted_volumes, volume_entry, next_item);
    mounted_volumes_count += 1;

    return 0;
}

/**
 * Returns the volume item that corresponds to the path
 * @param path
 * @param {optional} p_relpath the resultant relative path from the root
 * @return NULL on failure
 */
struct nexus_volume *
vfs_get_volume(const char * path, char ** p_relpath)
{
    const char * strptr = NULL;

    struct nexus_volume * volume       = NULL;
    struct volume_entry * volume_entry = NULL;

    int len = 0;

    TAILQ_FOREACH(volume_entry, mounted_volumes, next_item)
    {
        volume = volume_entry->volume;
        len    = volume_entry->datafolder_dirpath_len;

        if (memcmp(path, volume->datafolder_dirpath, len) == 0) {
            if (p_relpath) {
                // XXX there might be a smarter way to do this
                strptr = path + len;
                if (*strptr == '/') {
                    strptr++;
                }

                *p_relpath = strndup(strptr, PATH_MAX);
            }

            return volume;
        }
    }

    return NULL;
}

struct nexus_metadata *
vfs_read_metadata(struct nexus_dentry * dentry, struct path_builder * builder)
{
    struct nexus_metadata *      metadata = NULL;
    struct nexus_volume *        volume   = dentry->volume;

    struct metadata_operations * ops
        = (struct metadata_operations *)volume->private_data;

    size_t size = 0;

    metadata = ops->read(dentry, builder, &size);
    if (metadata == NULL) {
        log_error("reading metadata failed");
        return NULL;
    }

    // this means the data had not been allocated, let's create it
    if (size == 0) {
        metadata->buffer
            = nexus_generate_metadata(volume, &dentry->uuid, dentry->type);
    }

    metadata->timestamp = clock();

    // free the old metadata object
    if (dentry->metadata) {
        nexus_free(dentry->metadata);
    }

    dentry->metadata = metadata;

    return metadata;
}

// TODO
int
vfs_revalidate(struct nexus_dentry * dentry)
{
    return -1;
}

// volume management

struct nexus_volume *
alloc_volume(const char * metadata_dirpath, const char * datafolder_dirpath)
{
    struct nexus_volume * volume      = NULL;
    struct nexus_dentry * root_dentry = NULL;

    volume = (struct nexus_volume *)calloc(1, sizeof(struct nexus_volume));
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

    root_dentry->type   = NEXUS_DIR;
    root_dentry->volume = volume;
    TAILQ_INIT(&root_dentry->children);

    volume->root_dentry        = root_dentry;
    volume->metadata_dirpath   = strndup(metadata_dirpath, PATH_MAX);
    volume->datafolder_dirpath = strndup(datafolder_dirpath, PATH_MAX);
    volume->private_data       = default_metadata_ops;

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

struct nexus_metadata *
alloc_metadata(struct nexus_dentry * dentry, char * fpath, uint8_t * buffer)
{
    struct nexus_metadata * metadata
        = (struct nexus_metadata *)calloc(1, sizeof(struct nexus_metadata));

    if (!metadata) {
	log_error("allocation error");
        return NULL;
    }

    metadata->volume = dentry->volume;
    metadata->fpath = fpath;
    metadata->is_root_dirnode = (dentry->parent == NULL);
    metadata->buffer = buffer;
    metadata->timestamp = clock();

    return metadata;
}
