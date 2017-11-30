/**
 * File contains functions that manage Nexus volumes
 *
 * @author Judicael Djoko <jdb@djoko.me>
 */
#include <sys/stat.h>

#include "nexus_internal.h"

int
nexus_create_volume(char *              publickey_fpath,
                    struct supernode ** p_supernode,
                    struct dirnode **   p_root_dirnode,
                    struct volumekey ** p_sealed_volumekey)
{
    int                ret          = -1;
    struct supernode * supernode    = NULL;
    struct dirnode *   root_dirnode = NULL;
    struct volumekey * volkey       = NULL;
    struct uuid        supernode_uuid;
    struct uuid        root_uuid;

    /* 2 -- allocate our structs and call the enclave */
    supernode    = (struct supernode *)calloc(1, sizeof(struct supernode));
    root_dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    volkey       = (struct volumekey *)calloc(1, sizeof(struct volumekey));
    if (supernode == NULL || root_dirnode == NULL || volkey == NULL) {
        log_error("allocation error");
        goto out;
    }

    nexus_uuid(&supernode_uuid);
    nexus_uuid(&root_uuid);

    ret = backend_volume_create(&supernode_uuid,
                                &root_uuid,
                                publickey_fpath,
                                supernode,
                                root_dirnode,
                                volkey);

    if (ret != 0) {
        log_error("backend_volume_create FAILED ret=%d", ret);
        goto out;
    }

    *p_supernode         = supernode;
    *p_root_dirnode      = root_dirnode;
    *p_sealed_volumekey  = volkey;

    ret = 0;
out:
    if (ret) {
        if (supernode) {
            nexus_free(supernode);
        }

        if (root_dirnode) {
            nexus_free(root_dirnode);
        }

        if (volkey) {
            nexus_free(volkey);
        }
    }

    return ret;
}

// TODO
int
nexus_mount_volume(struct supernode * supernode,
                   struct volumekey * volumekey,
                   const char *       metadata_dir,
                   const char *       datafile_dir)
{
    int ret = -1;

    /* 1 -- if not logged in, exit */

    /* 2 -- Read the supernode */

    /* 3 -- Call the enclave */

    // add it to the vfs and call it a day
    ret = nexus_vfs_add_volume(&supernode->header, metadata_dir,
            datafile_dir);
    if (ret != 0) {
        log_error("nexus_vfs_add_volume ERROR");
        goto out;
    }
out:
    return ret;
}

int
nexus_login_volume(struct supernode * supernode,
                   struct volumekey * volumekey,
                   const char *       publickey_fpath,
                   const char *       privatekey_fpath)
{
    int ret = nexus_auth_backend(
        supernode, volumekey, publickey_fpath, privatekey_fpath);

    if (ret != 0) {
        log_error("backend authentication FAILED");
    }

    return ret;
}

int
nexus_init() {
    if (nexus_init_backend()) {
        log_error("initializing the backend failed");
        return -1;
    }

    if (nexus_vfs_init()) {
        log_error("could not initialize NeXUS-VFS");
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
