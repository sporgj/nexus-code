/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_backend.h>


static int
init(void)
{

    printf("Initializing Cleartext backend\n");

    return 0;
}

static void *
create_volume(struct nexus_volume * volume)
{
    struct supernode * supernode = NULL;

    struct nexus_uuid   supernode_uuid;
    struct nexus_key  * user_prv_key = NULL;
    struct nexus_key  * user_pub_key = NULL;

    supernode = create_supernode(&supernode_uuid, user_pub_key);
    
    
    if (supernode == NULL) {
	log_error("Could not create supernode\n");
	return NULL;
    }

    
    
    
    return NULL;
}


static struct nexus_backend_impl clear_impl = {
    .name          = "CLEARTEXT",
    .init          = init,
    .create_volume = create_volume
    
};


nexus_register_backend(clear_impl);
