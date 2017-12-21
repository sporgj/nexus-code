/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include "supernode.h"

#include <nexus_volume.h>
#include <nexus_datastore.h>

#include <nexus_encode.h>
#include <nexus_util.h>
#include <nexus_json.h>
#include <nexus_log.h>

#define USER_FLAG_OWNER 1

struct user_entry{
    char             * name;
    struct nexus_key * pub_key;    
    uint32_t flags;
};

struct supernode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;    
    struct nexus_uuid user_list_uuid;
    // hash of user list

    // hash of volume_config (Is this necessary?)

    uint32_t version;   
};



static int
__create_user_list(struct nexus_volume * volume,
		   struct supernode    * supernode, 
		   struct nexus_key    * user_pub_key)
{
    nexus_json_obj_t user_json = NEXUS_JSON_INVALID_OBJ; 
    nexus_json_obj_t user_arr  = NEXUS_JSON_INVALID_OBJ; 
    nexus_json_obj_t user      = NEXUS_JSON_INVALID_OBJ; 

    struct nexus_uuid user_list_uuid;
    
    char * key_str    = NULL;
    char * user_str   = NULL;
    char * key_base64 = NULL;

    int ret = 0;
    
    
    /* Create uuid for user list */
    nexus_uuid_gen(&user_list_uuid);
    
    
    key_str = nexus_key_to_str(user_pub_key);

    if (key_str == NULL) {
	log_error("Could not generate key string\n");
	return -1;
    }

    /* We double encode the key to base64 because PEM cannot be embedded in JSON */
    key_base64 = nexus_base64_encode((uint8_t *)key_str, strlen(key_str) + 1);
    
    
    /* Create top level json object */
    user_json = nexus_json_new_obj();

    /* Create user list as an array */
    user_arr  = nexus_json_add_array(user_json, "users");

    /* Add the 'owner' user to the array */
    user      = nexus_json_array_add_object(user_arr);
    
    /* Set fields in user object */
    nexus_json_add_string(user, "name", "owner");
    nexus_json_add_string(user, "key",  key_base64);

    /* Serialize user list to string */
    user_str = nexus_json_serialize(user_json);

    if (user_str == NULL) {
	log_error("Could not serialize user list\n");
	goto err;
    }

    /* Save user list string to metadata object */
    ret = nexus_datastore_add_uuid(volume->meta_data_store,
				   &user_list_uuid,
				   "/",
				   (uint8_t *)user_str,
				   strlen(user_str));

    if (ret == -1) {
	log_error("Could not add user_list to metadata store\n");
	goto err;
    }
    
    nexus_uuid_copy(&user_list_uuid, &supernode->user_list_uuid);
    
    nexus_free(key_str);
    nexus_free(key_base64);
    nexus_free(user_str);
    nexus_json_free(user_json);

    return 0;
    
 err:
    if (key_str)    nexus_free(key_str);
    if (user_str)   nexus_free(user_str);
    if (key_base64) nexus_free(key_str);

    if (user_json != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(user_json);
    }
    
    return -1;
    
}


int
create_supernode(struct nexus_volume * volume, 
		 struct nexus_key    * user_pub_key,
		 struct nexus_uuid   * supernode_uuid,
		 struct nexus_key    * volume_key)
{
    struct supernode * supernode = NULL;

    int ret = 0;

    supernode = calloc(sizeof(struct supernode), 1);

    if (supernode == NULL) {
	log_error("Cannot allocate supernode\n");
	return -1;
    }
    
    // create allocate uuid for supernode
    ret |= nexus_uuid_gen(supernode_uuid);
    
    if (ret != 0) {
	log_error("Could not generate supernode uuid\n");
	return -1;
    }
    

    // initialize user list with owner
    __create_user_list(volume, supernode, user_pub_key);

    // create root dir

    
    // save supernode


    return -1;
}
