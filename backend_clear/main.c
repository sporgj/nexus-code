/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_backend.h>
#include <nexus_user_data.h>
#include <nexus_volume.h>

#include <nexus_log.h>
#include <nexus_json.h>

#include "supernode.h"

struct backend_state {
    

};


static void *
init(nexus_json_obj_t backend_cfg)
{

    printf("Initializing Cleartext backend\n");

    return NULL;
}

int
init_volume(struct nexus_volume * volume,
	    void                * priv_data)
{
    struct supernode  * supernode    = NULL;
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

    
    supernode = supernode_create(volume, user_pub_key, &(volume->vol_key));
    
    if (supernode == NULL) {
	log_error("Could not create supernode\n");
	goto err;
    }

    nexus_uuid_copy(&(supernode->my_uuid), &(volume->supernode_uuid));

    
    nexus_free_key(user_prv_key);
    nexus_free_key(user_pub_key);
    
    return 0;

 err:

    if (user_prv_key) nexus_free_key(user_prv_key);
    if (user_pub_key) nexus_free_key(user_pub_key);
    
    return -1;
}



int
open_volume(struct nexus_volume * volume,
	    void                * priv_data)
{
    //    struct supernode * supernode    = NULL;
    struct nexus_key * user_prv_key = NULL;
    struct nexus_key * user_pub_key = NULL;

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



    
    //   supernode = supernode_load(supernode, user_pub_key, backend_state);


    
    
    nexus_free_key(user_prv_key);
    nexus_free_key(user_pub_key);
    
    return 0;

 err:

    if (user_prv_key) nexus_free_key(user_prv_key);
    if (user_pub_key) nexus_free_key(user_pub_key);
    
    return -1;
    
}


static struct nexus_backend_impl clear_impl = {
    .name        = "CLEARTEXT",
    .init        = init,
    .init_volume = init_volume,
    .open_volume = open_volume
    
};


nexus_register_backend(clear_impl);
