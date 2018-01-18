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

struct user {
    char * name;
    struct nexus_key pub_key;

    union {
	uint32_t flags;
	struct {
	    uint32_t admin : 1;
	    uint32_t rsvd  : 31;
	} __attribute__((packed));
    } __attribute__((packed));
    
};


struct user_list {
    struct nexus_uuid my_uuid;
    uint32_t          version;
    
    nexus_json_obj_t  users;
};

struct user * get_user(struct user_list * list,
		       char             * username);


struct user_list * user_list_create(char             * username,
				    struct nexus_key * owner_pub_key);

int user_list_store(struct nexus_volume * volume,
		    struct user_list    * user_list);

struct user_list * user_list_load(struct nexus_volume * volume,
				  struct nexus_uuid   * user_list_uuid);

void user_list_free(struct user_list * user_list);

