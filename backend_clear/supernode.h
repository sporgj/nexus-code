/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once
#include <stdint.h>

#include <nexus_uuid.h>
#include <nexus_key.h>

struct nexus_volume;



struct supernode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;    
    struct nexus_uuid user_list_uuid;
    // hash of user list

    // hash of volume_config (Is this necessary?)

    uint32_t version;   
};


struct supernode *
supernode_create(struct nexus_volume * volume,
		 struct nexus_key    * user_pub_key,
		 struct nexus_key    * volume_key);

int
supernode_store(struct nexus_volume * volume,
		struct supernode    * supernode);
