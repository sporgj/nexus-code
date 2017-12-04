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

// TODO
int
nexus_dirnode_lookup(struct dirnode *      dirnode,
                     char *                fname,
                     struct uuid *         uuid_dest,
                     nexus_fs_obj_type_t * p_type)
{
    return -1;
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

    int    ret  = -1;

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

// TODO
int
nexus_exit()
{
    return 0;
}
