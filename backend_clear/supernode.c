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
#include "users.h"



struct supernode *
supernode_create(struct nexus_key * user_pub_key,
		 struct user_list * user_list,
		 struct dirnode   * root_dir,
		 struct nexus_key * volume_key)
{
    struct supernode * supernode = NULL;
    struct nexus_key * tmp_key   = NULL;
    
    supernode = nexus_malloc(sizeof(struct supernode));

    // generate a volume key
    tmp_key = nexus_create_key(NEXUS_RAW_256_KEY);

    if (tmp_key == NULL) {
	log_error("Could not generate a volume key\n");
	goto err;
    }
    
    // generate uuid for supernode
    nexus_uuid_gen(&(supernode->my_uuid));

    nexus_uuid_copy(&(user_list->my_uuid), &(supernode->user_list_uuid));
    nexus_uuid_copy(&(root_dir->my_uuid),  &(supernode->root_uuid));
    

    nexus_copy_key(tmp_key, volume_key);
    nexus_free_key(tmp_key);
    
    return supernode;

 err:
    
    if (tmp_key)    nexus_free_key(tmp_key);
    if (supernode)  nexus_free(supernode);
    
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



struct supernode * 
supernode_load(struct nexus_volume * volume, 
	       struct nexus_uuid   * supernode_uuid)
{
    struct supernode * supernode      = NULL;
    nexus_json_obj_t   supernode_json = NEXUS_JSON_INVALID_OBJ;

    char     * json_str = NULL;
    uint32_t   json_len = 0;

    int ret = 0;

    /* Load UUID from metadata store */
    ret = nexus_datastore_get_uuid(volume->metadata_store,
				   supernode_uuid,
				   NULL,
				   (uint8_t **)&json_str,
				   &json_len);
    
    if (ret == -1) {
	char * uuid_str = nexus_uuid_to_alt64(supernode_uuid);
	log_error("Could not get supernode UUID (%s)\n", uuid_str);
	nexus_free(uuid_str);

	return NULL;
    }
    
    /* Parse Supernode */
    supernode_json = nexus_json_parse_str(json_str);

    if (supernode_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not parse supernode structure\n");
	goto err;
    }
    
    /* Allocate supernode */
    supernode = nexus_malloc(sizeof(struct supernode));
    

    /* Load UUIDs from JSON */
    {
	char * supernode_uuid_str = NULL;
	char * user_list_uuid_str = NULL;
	char *  root_dir_uuid_str = NULL;

	nexus_json_get_string(supernode_json, "uuid",      &supernode_uuid_str);
	nexus_json_get_string(supernode_json, "user_list", &user_list_uuid_str);
	nexus_json_get_string(supernode_json, "root_dir",   &root_dir_uuid_str);

	if ( (supernode_uuid_str == NULL) ||
	     (user_list_uuid_str == NULL) ||
	     ( root_dir_uuid_str == NULL) ) {
	    log_error("Invalid supernode structure\n");
	    goto err;	    
	}
	
	nexus_uuid_from_alt64(&(supernode->my_uuid),        supernode_uuid_str);
	nexus_uuid_from_alt64(&(supernode->user_list_uuid), user_list_uuid_str);
	nexus_uuid_from_alt64(&(supernode->root_uuid),       root_dir_uuid_str);
	
	if (nexus_uuid_compare(&(supernode->my_uuid), supernode_uuid) != 0) {
	    log_error("UUID Mismatch in supernode\n");
	    goto err;
	}
    }
    
    nexus_free(json_str);
    nexus_json_free(supernode_json);

    return supernode;

 err:

    if (supernode) nexus_free(supernode);
    if (json_str)  nexus_free(json_str);
    
    if (supernode_json != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(supernode_json);
    }
    
    return NULL;    
}



void
supernode_free(struct supernode * supernode)
{
    return;

}
