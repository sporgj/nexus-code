#include <sys/stat.h>

#include <nexus_volume.h>
#include <nexus_key.h>

#include <nexus_util.h>
#include <nexus_log.h>

#include "nexus_internal.h"


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
nexus_mount_volume(char * volume_path,
                   char * vol_key_path,
                   char * pub_key_path,
                   char * prv_key_path)
{
    struct nexus_volume * volume  = NULL;

    struct nexus_key    * vol_key = NULL;
    struct nexus_key    * pub_key = NULL;
    struct nexus_key    * prv_key = NULL;
    
    int    ret  = -1;


    /* Grab the keys */
    vol_key = nexus_load_key_from_file(vol_key_path);
    pub_key = nexus_load_key_from_file(pub_key_path);
    prv_key = nexus_load_key_from_file(prv_key_path);


    if (vol_key == NULL) {
	log_error("Could not load volume key (%s)\n", vol_key_path);
	goto err;
    }
	
    if (pub_key == NULL) {
	log_error("Could not load public key (%s)\n", pub_key_path);
	goto err;
    }
    
    if (prv_key == NULL) {
	log_error("Could not load private_key (%s)\n", prv_key_path);
	goto err;
    }

           
    /* Read in volume information */
    volume = nexus_load_volume(volume_path);

    if (volume == NULL) {
	log_error("Could not load volume (%s)\n", volume_path);
    }
    
    /* Activate the backend and metadata components */
    
    
    /* Return handle to volume */



    
 #if 0
    // mount it
   
    volume = metadata_mount_volume(metadata_dirpath,
				   datafolder_dirpath,
				   volumekey_fpath);

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

#endif
   

    return ret;
err:
    if (vol_key) nexus_free(vol_key);
    if (pub_key) nexus_free(pub_key);
    if (prv_key) nexus_free(prv_key);

    if (volume) nexus_close_volume(volume);    


    return -1;
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
