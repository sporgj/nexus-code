#include "nexus_mstore_internal.h"

#define SUPERNODE_FILENAME "supernode"

struct metadata_operations * default_metadata_ops = NULL;

int
metadata_create_volume(struct supernode * supernode,
                       struct dirnode *   root_dirnode,
                       struct volumekey * volumekey,
                       const char *       metadata_dirpath,
                       const char *       volumekey_fpath)
{
    char * supernode_fpath = strndup(metadata_dirpath, PATH_MAX);
    char * dirnode_fpath   = strndup(metadata_dirpath, PATH_MAX);

    size_t size = 0;
    int    ret  = -1;

    // form the filepaths and write it out
    supernode_fpath = filepath_from_name(supernode_fpath, SUPERNODE_FILENAME);
    dirnode_fpath
        = filepath_from_uuid(dirnode_fpath, &root_dirnode->header.uuid);

    size = supernode->header.total_size;
    if (write_file(supernode_fpath, (uint8_t *)supernode, size)) {
        log_error("writing supernode (%s) FAILED", supernode_fpath);
        goto out;
    }

    size = root_dirnode->header.total_size;
    if (write_file(dirnode_fpath, (uint8_t *)root_dirnode, size)) {
        log_error("writing dirnode (%s) FAILED", dirnode_fpath);
        goto out;
    }

    size = sizeof(struct volumekey);
    if (write_file(volumekey_fpath, (uint8_t *)volumekey, size)) {
        log_error("writing volumekey (%s) FAILED", volumekey_fpath);
        goto out;
    }

    ret = 0;
out:
    if (dirnode_fpath) {
        nexus_free(dirnode_fpath);
    }

    if (supernode_fpath) {
        nexus_free(supernode_fpath);
    }

    return ret;
}

struct nexus_volume *
metadata_mount_volume(const char * metadata_dirpath,
                      const char * datafolder_dirpath,
                      const char * volumekey_fpath)
{
    struct nexus_volume * volume    = NULL;
    struct volumekey *    volumekey = NULL;
    struct supernode *    supernode = NULL;

    char * temp_fpath = NULL;

    size_t size = 0;
    int    err  = -1;

    // read the supernode
    temp_fpath = strndup(metadata_dirpath, PATH_MAX);
    temp_fpath = filepath_from_name(temp_fpath, SUPERNODE_FILENAME);

    err = read_file(temp_fpath, (uint8_t **)&supernode, &size);
    if (err != 0) {
        nexus_free(temp_fpath);
        log_error("reading supernode (%s) FAILED", temp_fpath);
        return NULL;
    }

    err = read_file(volumekey_fpath, (uint8_t **)&volumekey, &size);
    if (err != 0) {
        log_error("reading volumekey (%s) FAILED", volumekey_fpath);
        goto out;
    }

    // allocate the volume and initialize the fields
    volume = alloc_volume(metadata_dirpath, datafolder_dirpath);
    if (volume == NULL) {
        log_error("allocation error");
        goto out;
    }

    volume->supernode = supernode;
    volume->volumekey = volumekey;

    memcpy(&volume->root_dentry->uuid,
           &volume->supernode->header.root_uuid,
           sizeof(struct uuid));

    if (vfs_add_volume(volume)) {
        log_error("adding volume FAILED");
        goto out;
    }

    err = 0;
out:
    nexus_free(temp_fpath);

    if (err) {
        if (supernode) {
            nexus_free(supernode);
        }

        if (volumekey) {
            nexus_free(volumekey);
        }

        free_volume(volume);

        return NULL;
    }

    return volume;
}

// TODO
void
metadata_umount_volume(struct nexus_volume * volume)
{
}

struct nexus_metadata *
metadata_get_metadata(const char * dirpath)
{
    struct nexus_dentry * dentry = NULL;

    struct nexus_volume * volume = NULL;

    char * relative_path = NULL;

    volume = vfs_get_volume(dirpath, &relative_path);
    if (!volume) {
        log_error("vfs_get_volume() FAILED");
        return NULL;
    }

    dentry = nexus_dentry_lookup(volume->root_dentry, relative_path);
    nexus_free(relative_path);

    if (!dentry) {
        log_error("nexus_dentry_lookup() FAILED");
        return NULL;
    }

    return dentry->metadata;
}

void
metadata_put_metadata(struct nexus_metadata * metadata)
{
    // TODO
}

int 
metadata_write_dirnode(struct nexus_metadata * metadata,
                       struct dirnode *        dirnode)
{
    struct dirnode *             old_dirnode = metadata->dirnode;
    struct metadata_operations * ops
        = (struct metadata_operations *)metadata->private_data;

    metadata->dirnode = dirnode;
    if (ops->write(metadata, dirnode->header.total_size)) {
        // restore the original dirnode
        metadata->dirnode = old_dirnode;
        log_error("could not write metadata (%s)", metadata->fpath);
        return -1;
    }

    // otherwise, deallocate the old
    free(old_dirnode);

    return 0;
}

int
metadata_create_metadata(struct nexus_metadata * parent_metadata,
                         struct uuid *           uuid,
                         nexus_fs_obj_type_t     type)
{
    struct metadata_operations * ops
        = (struct metadata_operations *)parent_metadata->private_data;

    return ops->create(parent_metadata, uuid, type);
}

int
metadata_delete_metadata(struct nexus_metadata * parent_metadata,
                         struct uuid *           uuid)
{
    struct metadata_operations * ops
        = (struct metadata_operations *)parent_metadata->private_data;

    return ops->delete(parent_metadata, uuid);
}

int
nexus_init_metadata_store()
{
    log_debug("Initializing metadata store");

    if (nexus_vfs_init()) {
        log_error("Could not initialize the VFS");
    }

    // for now, let's just statically default to the flatdir implementation
    default_metadata_ops = &flatdir_metadata_ops;
    return 0;
}

int
nexus_exit_metadata_store()
{
    log_debug("Shutting down metadata store...");

    nexus_vfs_exit();

    return 0;
}
