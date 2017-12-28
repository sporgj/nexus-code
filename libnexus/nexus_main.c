/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <sys/stat.h>

#include <nexus_volume.h>
#include <nexus_backend.h>
#include <nexus_datastore.h>
#include <nexus_user_data.h>

#include <nexus_key.h>

#include <nexus_util.h>
#include <nexus_log.h>



#if 0
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
#endif


int
nexus_init()
{

    printf("Initializing Nexus\n");

    nexus_config_init();
    nexus_backend_init();
    nexus_datastores_init();
    

    return 0;
}


int
nexus_deinit()
{
    printf("Deinitializing Nexus\n");
    return 0;
}

int
nexus_setup()
{
    return nexus_create_user_data();
}




#if 0

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


#endif
