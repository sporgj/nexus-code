/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_json.h>
#include <nexus_util.h>
#include <nexus_log.h>


#include "dirnode.h"

struct dirnode *
dirnode_create(struct nexus_volume * volume,
	       struct nexus_uuid   * parent_uuid)
{
    struct dirnode * new_dir = NULL;

    int ret = 0;
    
    new_dir = nexus_malloc(sizeof(struct dirnode));
    
    nexus_uuid_gen(&(new_dir->my_uuid));

    if (parent_uuid == NULL) {
	new_dir->root_dir = 1;
    } else {
	nexus_uuid_copy(parent_uuid, &(new_dir->parent_uuid));
    }
    
    new_dir->version = 1;
    new_dir->file_list = nexus_json_new_arr("entries");

    
    ret = dirnode_store(volume, new_dir);

    if (ret == -1) {
	log_error("Could not store new dirnode\n");

	nexus_json_free(new_dir->file_list);
	nexus_free(new_dir);
	return NULL;
    }
    
    return new_dir;
}


void
dirnode_free(struct dirnode * dirnode)
{
    nexus_json_free(dirnode->file_list);
    nexus_free(dirnode);
    return;
}
    

int
dirnode_store(struct nexus_volume * volume,
	      struct dirnode      * dirnode)
{
    nexus_json_obj_t dir_json = NEXUS_JSON_INVALID_OBJ;

    char * my_uuid_alt64     = NULL;
    char * parent_uuid_alt64 = NULL;
    
    char * dir_str = NULL;

    int ret = 0;
    
    my_uuid_alt64     = nexus_uuid_to_alt64(&(dirnode->my_uuid));
    parent_uuid_alt64 = nexus_uuid_to_alt64(&(dirnode->parent_uuid));    
    
    dir_json = nexus_json_new_obj("dirnode");

    nexus_json_add_string(dir_json, "uuid",    my_uuid_alt64);
    nexus_json_add_u32   (dir_json, "version", dirnode->version);
    nexus_json_add_u8    (dir_json, "rootdir", dirnode->root_dir);

    if (dirnode->root_dir == 0) {
	nexus_json_add_string(dir_json, "parent",  parent_uuid_alt64);
    }
    
    nexus_json_splice(dir_json, dirnode->file_list);
    dir_str = nexus_json_serialize(dir_json);
    nexus_json_split(dirnode->file_list);

    if (dir_str == NULL) {
	log_error("Could not serialize dirnode\n");
	goto err;
    }
    
    ret = nexus_datastore_put_uuid(volume->metadata_store,
				   &(dirnode->my_uuid),
				   NULL,
				   (uint8_t *)dir_str,
				   strlen(dir_str) + 1);


    if (ret == -1) {
	log_error("Could not store dirnode\n");
	goto err;
    }

    nexus_json_free(dir_json);
    nexus_free(my_uuid_alt64);
    nexus_free(parent_uuid_alt64);
    nexus_free(dir_str);
    
    return 0;

 err:

    if (my_uuid_alt64)     nexus_free(my_uuid_alt64);
    if (parent_uuid_alt64) nexus_free(parent_uuid_alt64);
    if (dir_str)           nexus_free(dir_str);
    
    if (dir_json != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(dir_json);
    }

    return -1;
}
