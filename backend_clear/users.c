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

#include "users.h"



struct user *
get_user(struct user_list * list,
	 char             * username)
{
    nexus_json_obj_t user_iter = NEXUS_JSON_INVALID_OBJ;
    
    if (list->users == NEXUS_JSON_INVALID_OBJ) {
	log_error("Invalid user list\n");	
	return NULL;
    }

    nexus_json_arr_foreach(user_iter, list->users) {
	

    }
	

    
    return NULL;
}


struct user_list *
user_list_create(char             * username, 
		 struct nexus_key * owner_pub_key)
{
    struct user_list * new_list = NULL;
    
    nexus_json_obj_t user_arr  = NEXUS_JSON_INVALID_OBJ; 
    nexus_json_obj_t user      = NEXUS_JSON_INVALID_OBJ; 
    
    char * key_str   = NULL;
    char * key_alt64 = NULL;
    
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
    nexus_json_add_string(user, "name",  username);
    nexus_json_add_string(user, "key",   key_alt64);
    nexus_json_add_u8    (user, "admin", 1);
    
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



struct user_list *
user_list_load(struct nexus_volume * volume,
	       struct nexus_uuid   * user_list_uuid)
{
    struct user_list * user_list      = NULL;
    nexus_json_obj_t   user_list_json = NEXUS_JSON_INVALID_OBJ;

    char     * json_str = NULL;
    uint32_t   json_len = 0;

    int ret = 0;

    /* Load UUID from metadata store */
    ret = nexus_datastore_get_uuid(volume->metadata_store,
				   user_list_uuid,
				   NULL,
				   (uint8_t **)&json_str,
				   &json_len);
    
    if (ret == -1) {
	char * uuid_str = nexus_uuid_to_alt64(user_list_uuid);
	log_error("Could not get user_list UUID (%s)\n", uuid_str);
	nexus_free(uuid_str);

	return NULL;
    }

    /* Parse User List */
    user_list_json = nexus_json_parse_str(json_str);

    if (user_list_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not parse user_list structure\n");
	goto err;
    }

    /* Allocate User List */
    user_list = nexus_malloc(sizeof(struct user_list));

    /* Set fields */
    {
	char * user_list_uuid_str = NULL;
	
	nexus_json_get_string(user_list_json, "uuid", &user_list_uuid_str);

	if (user_list_uuid_str == NULL) {
	    log_error("Invalid User list structure (Missing uuid)\n");	    
	    goto err;
	}

	if (nexus_uuid_compare(&(user_list->my_uuid), user_list_uuid) != 0) {
	    log_error("UUID mismatch in user list\n");
	    goto err;
	}
	
	
	ret = nexus_json_get_u32(user_list_json, "version", &(user_list->version));

	if (ret == -1) {
	    log_error("Invalid User list structure (Missing version)\n");
	    goto err;
	}

	user_list->users = nexus_json_get_object(user_list_json, "users");	

	if (user_list->users == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid User list structure (Missing users)\n");
	    goto err;
	}

	// split the user list out of the serialized state (This lets us delete the enclosing json) 
	nexus_json_split(user_list->users);
	
    }
    
    nexus_free(json_str);
    nexus_json_free(user_list_json);
        
    return user_list;

    
 err:
    if (user_list) nexus_free(user_list);
    if (json_str)  nexus_free(json_str);

    if (user_list_json != NEXUS_JSON_INVALID_OBJ) {
	nexus_json_free(user_list_json);
    }

    return NULL;
}


void
user_list_free(struct user_list * user_list)
{
    nexus_json_free(user_list->users);
    nexus_free(user_list);
}
