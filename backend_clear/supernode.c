/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */



#include <nexus_volume.h>
#include <nexus_datastore.h>

#include <nexus_encode.h>
#include <nexus_util.h>
#include <nexus_json.h>
#include <nexus_log.h>


#include "supernode.h"
#include "dirnode.h"
#include "user_list.h"



struct supernode *
supernode_create(struct nexus_volume * volume, 
		 struct nexus_key    * user_pub_key,
		 struct nexus_key    * volume_key)
{
    struct supernode * supernode = NULL;
    struct dirnode   * root_dir  = NULL;
    struct user_list * user_list = NULL;
    
    int ret = 0;

    supernode = nexus_malloc(sizeof(struct supernode));
    
    // generate uuid for supernode
    nexus_uuid_gen(&(supernode->my_uuid));
    
    // initialize user list with owner
    user_list = user_list_create(volume, user_pub_key);

    if (user_list == NULL) {
	log_error("Could not create user list\n");
	goto err;
    }

    nexus_uuid_copy(&(user_list->my_uuid), &(supernode->user_list_uuid));

    
    // create root dir
    root_dir = dirnode_create(volume, NULL);

    if (root_dir == NULL) {
	log_error("Could not create dirnode\n");
	goto err;
    }

    nexus_uuid_copy(&(root_dir->my_uuid), &(supernode->root_uuid));
    
    // save supernode
    ret = supernode_store(volume, supernode);

    if (ret == -1) {
	log_error("Could not store supernode\n");
	goto err;
    }

    return supernode;

 err:

    if (user_list) {
	nexus_datastore_del_uuid(volume->metadata_store, &(user_list->my_uuid), NULL);
	user_list_free(user_list);
    }

    if (root_dir) {
	nexus_datastore_del_uuid(volume->metadata_store, &(root_dir->my_uuid), NULL);
	dirnode_free(root_dir);
    }
    
    if (supernode) nexus_free(supernode);
    
    return NULL;

}


int
supernode_store(struct nexus_volume * volume,
		struct supernode    * supernode)
{
    nexus_json_obj_t supernode_json = NEXUS_JSON_INVALID_OBJ;

    char * my_uuid_alt64   = NULL;
    char * root_uuid_alt64 = NULL;
    char * user_uuid_alt64 = NULL;
    
    char * json_str = NULL;
    int    ret      = 0;

    my_uuid_alt64   = nexus_uuid_to_alt64(&(supernode->my_uuid));
    root_uuid_alt64 = nexus_uuid_to_alt64(&(supernode->root_uuid));
    user_uuid_alt64 = nexus_uuid_to_alt64(&(supernode->user_list_uuid));
    
    supernode_json = nexus_json_new_obj("supernode");

    nexus_json_add_string(supernode_json, "uuid",      my_uuid_alt64);
    nexus_json_add_string(supernode_json, "root_dir",  root_uuid_alt64);
    nexus_json_add_string(supernode_json, "user_list", user_uuid_alt64);
    nexus_json_add_u8    (supernode_json, "version",   supernode->version);

    json_str = nexus_json_serialize(supernode_json);

    ret = nexus_datastore_put_uuid(volume->metadata_store,
				   &(supernode->my_uuid),
				   NULL,
				   (uint8_t *)json_str,
				   strlen(json_str) + 1);

    if (ret == -1) {
	log_error("Could not store supernode\n");
	goto err;
    }


    nexus_json_free(supernode_json);
    nexus_free(my_uuid_alt64);
    nexus_free(root_uuid_alt64);
    nexus_free(user_uuid_alt64);
    nexus_free(json_str);

    return 0;
 err:
    
    if (my_uuid_alt64)   nexus_free(my_uuid_alt64);
    if (root_uuid_alt64) nexus_free(root_uuid_alt64);
    if (user_uuid_alt64) nexus_free(user_uuid_alt64);
    if (json_str)        nexus_free(json_str);
    
    if (supernode_json != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(supernode_json);
    }

    return -1;
}
