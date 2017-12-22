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

struct user_list {
    struct nexus_uuid my_uuid;
    uint32_t          version;
    
    nexus_json_obj_t  users;
};


struct user_list * user_list_create(struct nexus_volume * volume,
				    struct nexus_key    * owner_pub_key);

struct user_list * user_list_load(struct nexus_volume * volume,
				  struct nexus_uuid   * user_list_uuid);

void user_list_free(struct user_list * user_list);

int user_list_store(struct nexus_volume * volume,
		    struct user_list    * user_list);
