/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#pragma once

#include <stdint.h>

#include <nexus_volume.h>


#include <nexus_uuid.h>
#include <nexus_json.h>


typedef enum {
    NEXUS_DENTRY_INVALID = 0,
    NEXUS_DENTRY_FILE    = 1,
    NEXUS_DENTRY_DIR     = 2
} nexus_dentry_type_t;


struct dirnode {
    struct nexus_uuid my_uuid;
    
    struct nexus_uuid parent_uuid; // Do we need this??

    uint32_t version;

    uint8_t root_dir; 

    nexus_json_obj_t file_list;
};



struct dirnode * dirnode_create(struct nexus_volume * volume,
				struct nexus_uuid   * parent_uuid);


struct dirnode * dirnode_load(struct nexus_volume * volume,
			      struct nexus_uuid   * dirnode_uuid);


void dirnode_free(struct dirnode * dirnode);

int dirnode_store(struct nexus_volume * volume,
		  struct dirnode      * dirnode);



nexus_dentry_type_t dirnode_get_entry(struct dirnode    * dirnode,
				      char              * name,		      
				      struct nexus_uuid * uuid);


int dirnode_add_entry(struct dirnode      * dirnode,
		      char                * name,
		      nexus_dentry_type_t   type,
		      struct nexus_uuid   * uuid);
