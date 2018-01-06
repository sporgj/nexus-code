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

#include "user_list.h"



struct user_list *
user_list_create(struct nexus_volume * volume,
		 struct nexus_key    * owner_pub_key)
{
    struct user_list * new_list = NULL;
    
    nexus_json_obj_t user_arr  = NEXUS_JSON_INVALID_OBJ; 
    nexus_json_obj_t user      = NEXUS_JSON_INVALID_OBJ; 
    
    char * key_str   = NULL;
    char * key_alt64 = NULL;

    int ret = 0;
    
    new_list = nexus_malloc(sizeof(struct user_list));

    /* Create uuid for user list */
    nexus_uuid_gen(&(new_list->my_uuid));
    new_list->version = 1;
    new_list->users   = nexus_json_new_arr("users");    /* Create user list as an array */

    
    key_str = nexus_key_to_str(owner_pub_key);

    if (key_str == NULL) {
	log_error("Could not generate key string\n");
	goto err;
    }

    /* We double encode the key to alt64 because PEM cannot be embedded in JSON */
    key_alt64 = nexus_alt64_encode((uint8_t *)key_str, strlen(key_str) + 1);    
    
    user      = nexus_json_array_add_object(new_list->users);     /* Add the 'owner' user to the array */

    /* Set fields in user object */
    nexus_json_add_string(user, "name", "owner");
    nexus_json_add_string(user, "key",  key_alt64);


    ret = user_list_store(volume, new_list);

    if (ret == -1) {
	log_error("Could not store user_list\n");
	goto err;
    }
    
    nexus_free(key_str);
    nexus_free(key_alt64);

    return new_list;
    
 err:
    if (key_str)   nexus_free(key_str);
    if (key_alt64) nexus_free(key_alt64);
    if (new_list)  nexus_free(new_list);
    
    if (user_arr != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(user_arr);
    }
    
    return NULL;
    
}




int
user_list_store(struct nexus_volume * volume,
		struct user_list    * user_list)
{

    nexus_json_obj_t list_json = NEXUS_JSON_INVALID_OBJ;
    
    char * my_uuid_alt64 = NULL;
    char * json_str      = NULL;

    int ret = 0;

    my_uuid_alt64 = nexus_uuid_to_alt64(&(user_list->my_uuid));

    list_json = nexus_json_new_obj("user_list");

    nexus_json_add_string(list_json, "uuid",    my_uuid_alt64);
    nexus_json_add_u32   (list_json, "version", user_list->version);

    nexus_json_splice(list_json, user_list->users);
    json_str = nexus_json_serialize(list_json);
    nexus_json_split(user_list->users);

    if (json_str == NULL) {
	log_error("Could not serialize user_list\n");
	goto err;
    }
    
    /* Save user list string to metadata object */
    ret = nexus_datastore_put_uuid(volume->metadata_store,
				   &(user_list->my_uuid),
				   NULL,
				   (uint8_t *)json_str,
				   strlen(json_str));

    if (ret == -1) {
	log_error("Could not add user_list to metadata store\n");
	goto err;
    }

    nexus_free(json_str);
    nexus_free(my_uuid_alt64);
    nexus_json_free(list_json);

    return 0;

 err:

    if (my_uuid_alt64) nexus_free(my_uuid_alt64);
    if (json_str)      nexus_free(json_str);

    if (list_json != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(list_json);
    }

    return -1;
}



void
user_list_free(struct user_list * user_list)
{
    nexus_json_free(user_list->users);
    nexus_free(user_list);
}
