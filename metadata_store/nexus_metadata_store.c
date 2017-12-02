#include "nexus_mstore_internal.h"

#define SUPERNODE_FILENAME "supernode"

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

        return NULL;
    }

    return volume;
}

// TODO
void
metadata_umount_volume(struct nexus_volume * volume)
{
}
