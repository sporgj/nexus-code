/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_backend.h>
#include <nexus_user_data.h>
#include <nexus_util.h>
#include <nexus_volume.h>

#include <nexus_log.h>
#include <nexus_json.h>
#include <nexus_config.h>

#include "supernode.h"
#include "backend.h"
#include "users.h"
#include "dirnode.h"




static void *
init(nexus_json_obj_t backend_cfg)
{
    struct backend_state * state;
    
    printf("Initializing Cleartext backend\n");

    state = nexus_malloc(sizeof(struct backend_state));

    return state;
}

static int
volume_init(struct nexus_volume * volume,
	    void                * priv_data)
{
    //    struct backend_state * backend_info = priv_data;
    
    struct supernode  * supernode    = NULL;
    struct dirnode    * root_dir     = NULL;
    struct user_list  * user_list    = NULL;

    struct nexus_key  * user_prv_key = NULL;
    struct nexus_key  * user_pub_key = NULL;
    
    
    user_prv_key = nexus_get_user_key();

    if (user_prv_key == NULL) {
	log_error("Could not retrieve user key\n");
	return -1;
    }

    user_pub_key = nexus_derive_key(NEXUS_MBEDTLS_PUB_KEY, user_prv_key);
    
    if (user_pub_key == NULL) {
	log_error("Could not derive user public key\n");
	goto err;
    }


    /* Create user list */
    user_list = user_list_create(nexus_config.username, user_pub_key);

    if (user_list == NULL) {
	log_error("Could not create user list\n");
	goto err;
    }

    
    /* Create root dir */
    root_dir = dirnode_create(NULL);

    if (root_dir == NULL) {
	log_error("Could not create dirnode\n");
	goto err;
    }

    /* Create supernode */
    supernode = supernode_create(user_pub_key, user_list, root_dir, &(volume->vol_key));
    
    if (supernode == NULL) {
	log_error("Could not create supernode\n");
	goto err;
    }


    /* Serialize */
      dirnode_store(volume, root_dir);  
    user_list_store(volume, user_list);
    supernode_store(volume, supernode);
    

    nexus_uuid_copy(&(supernode->my_uuid), &(volume->supernode_uuid));

    
    nexus_free_key(user_prv_key);
    nexus_free_key(user_pub_key);

    user_list_free(user_list);
    dirnode_free(root_dir);

    
    return 0;

    
 err:

    if (user_list) {
	nexus_datastore_del_uuid(volume->metadata_store, &(user_list->my_uuid), NULL);
	user_list_free(user_list);
    }

    if (root_dir) {
	nexus_datastore_del_uuid(volume->metadata_store, &(root_dir->my_uuid), NULL);
	dirnode_free(root_dir);
    }
    
    if (user_prv_key) nexus_free_key(user_prv_key);
    if (user_pub_key) nexus_free_key(user_pub_key);
    
    return -1;
}



static int
volume_open(struct nexus_volume * volume,
	    void                * priv_data)
{
    struct backend_state * backend_info = priv_data;
	
    struct supernode * supernode = NULL;
    struct user_list * user_list = NULL;
    struct user      * user      = NULL;

    struct nexus_key * user_prv_key = NULL;
    struct nexus_key * user_pub_key = NULL;
    
    
    /* open the supernode */
    supernode = supernode_load(volume, &(volume->supernode_uuid));

    if (supernode == NULL) {
	log_error("Could not load supernode for volume (%s)\n", volume->volume_path);
	goto err;
    }
    
    /* Load the user list */
    user_list = user_list_load(volume, &(supernode->user_list_uuid));
    
    if (user_list == NULL) {
	log_error("Could not load user list for volume (%s)\n", volume->volume_path);
	goto err;
    }

    
    /* Authenticate user */
    {
	
	user_prv_key = nexus_get_user_key();
	
	if (user_prv_key == NULL) {
	    log_error("Could not retrieve user key\n");
	    return -1;
	}
	
	user_pub_key = nexus_derive_key(NEXUS_MBEDTLS_PUB_KEY, user_prv_key);
	
	if (user_pub_key == NULL) {
	    log_error("Could not derive user public key\n");
	    goto err;
	}

	user = get_user(user_list, nexus_config.username);

	if (user == NULL) {
	    log_error("Could not authenticate user\n");
	    goto err;
	}
    }
    

    /* Activate the volume */
    backend_info->supernode = supernode;
    backend_info->user_list = user_list;
    backend_info->user      = user;
    
    
    nexus_free_key(user_prv_key);
    nexus_free_key(user_pub_key);	
	
    
    return 0;

 err:

    if (user_prv_key) nexus_free_key(user_prv_key);
    if (user_pub_key) nexus_free_key(user_pub_key);
    if (supernode)    supernode_free(supernode);

    
    return -1;
    
}

static int
fs_create(struct nexus_volume * volume,
	  char                * path,
	  nexus_dirent_type_t   type,
	  struct nexus_stat   * stat,
	  void                * priv_data)
{


    printf("Create A file...\n");



    return -1;
}

static struct nexus_backend_impl clear_impl = {
    .name        = "CLEARTEXT",
    .init        = init,
    .volume_init = volume_init,
    .volume_open = volume_open,


    .fs_create   = fs_create
    
};


nexus_register_backend(clear_impl);
