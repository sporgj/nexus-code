/**
 * File contains functions that manage Nexus volumes
 *
 * @author Judicael Djoko <jdb@djoko.me>
 */
#include <sys/stat.h>

#include <uuid/uuid.h>

#include "nexus_internal.h"

void
nexus_uuid(struct uuid * uuid)
{
    uuid_generate((uint8_t *)uuid);
}

int
nexus_dirnode_lookup(struct dirnode *      dirnode,
                     char *                fname,
                     struct uuid *         uuid_dest,
                     nexus_fs_obj_type_t * p_type)
{
    return backend_dirnode_find_by_name(dirnode, fname, uuid_dest, p_type);
}

void *
nexus_generate_metadata(struct nexus_volume * volume,
                        struct uuid *         uuid,
                        nexus_fs_obj_type_t   type)
{
    struct dirnode * dirnode = NULL;

    struct uuid * root_uuid = &volume->supernode->header.root_uuid;

    int ret = -1;

    if (type == NEXUS_DIR) {
        ret = backend_dirnode_new(uuid, root_uuid, &dirnode);
        if (ret != 0) {
            log_error("backend_dirnode_new() FAILED");
            return NULL;
        }

        return dirnode;
    }

    return NULL;
}

int
nexus_create_volume(const char * metadata_dirpath,
                    const char * publickey_fpath,
                    const char * volumekey_fpath)
{
    struct supernode supernode;
    struct dirnode   root_dirnode;
    struct volumekey volumekey;

    struct uuid supernode_uuid;
    struct uuid root_uuid;

    FILE * fd = NULL;

    int ret = -1;

    nexus_uuid(&supernode_uuid);
    nexus_uuid(&root_uuid);

    ret = backend_volume_create(&supernode_uuid,
                                &root_uuid,
                                publickey_fpath,
                                &supernode,
                                &root_dirnode,
                                &volumekey);

    if (ret != 0) {
        log_error("backend_volume_create FAILED ret=%d", ret);
        goto out;
    }

    ret = metadata_create_volume(&supernode,
                                 &root_dirnode,
                                 &volumekey,
                                 metadata_dirpath,
                                 volumekey_fpath);

    if (ret != 0) {
        log_error("metadata_create_volume() FAILED");
        goto out;
    }

    ret = 0;
out:
    if (fd) {
        fclose(fd);
    }

    return ret;
}

int
nexus_mount_volume(const char * metadata_dirpath,
                   const char * datafolder_dirpath,
                   const char * volumekey_fpath,
                   const char * publickey_fpath,
                   const char * privatekey_fpath)
{
    struct nexus_volume * volume = NULL;

    int ret = -1;

    // mount it
    volume = metadata_mount_volume(
        metadata_dirpath, datafolder_dirpath, volumekey_fpath);

    if (volume == NULL) {
        log_error("mouting the volume failed");
        goto out;
    }

    // authenticate with the backend
    ret = nexus_auth_backend(volume->supernode,
                             volume->volumekey,
                             publickey_fpath,
                             privatekey_fpath);

    if (ret != 0) {
        log_error("backend authentication FAILED");
        goto out;
    }

    ret = 0;
out:
    if (ret) {
        metadata_umount_volume(volume);
    }

    return ret;
}

int
nexus_init()
{
    if (nexus_init_backend()) {
        log_error("initializing the backend failed");
        return -1;
    }

    if (nexus_init_metadata_store()) {
        log_error("initializing metadata store failed");
        return -1;
    }

    return 0;
}

int
nexus_exit()
{
    int ret = 0;

    if (nexus_exit_backend()) {
        ret = -1;
        log_error("deininitalizing backend failed");
    }

    if (nexus_exit_metadata_store()) {
        ret = -1;
        log_error("exiting metadata store FAILED");
    }

    return ret;
}
