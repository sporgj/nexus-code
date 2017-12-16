/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_user_data.h>


#include <nexus_config.h>

#include <nexus_util.h>
#include <nexus_log.h>
#include <nexus_json.h>


#define NEXUS_VOLUME_KEY_FILENAME    "nexus_volume_keys"






static nexus_json_obj_t
__get_volume_key_list()
{
    nexus_json_obj_t key_json = NEXUS_JSON_INVALID_OBJ;

    char * key_file_path  = NULL;

    int ret = 0;

    ret = asprintf(&key_file_path, "%s/%s", nexus_config.user_data_dir, NEXUS_VOLUME_KEY_FILENAME);

    if (ret == -1) {
	log_error("Could not allocate volume key string\n");
	return NEXUS_JSON_INVALID_OBJ;
    }
	
    key_json = nexus_json_parse_file(key_file_path);
    
    nexus_free(key_file_path);

    if (key_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not parse volume key file\n");
	return NEXUS_JSON_INVALID_OBJ;
    }

  
    return key_json;
}


static int
__save_volume_key_list(nexus_json_obj_t key_json)
{
    char * key_file_path = NULL;

    int ret = 0;

    ret = asprintf(&key_file_path, "%s/%s", nexus_config.user_data_dir, NEXUS_VOLUME_KEY_FILENAME);

    if (ret == -1) {
	log_error("Could not allocate volume key string\n");
	return -1;
    }

    ret = nexus_json_serialize_to_file(key_json, key_file_path);

    nexus_free(key_file_path);
    
    if (ret == -1) {
	log_error("Could not write key file\n");
	return -1;
    }

    return 0;
}

static int
__create_volume_key_list()
{
    nexus_json_obj_t key_list = NEXUS_JSON_INVALID_OBJ;

    int ret = 0;
    
    key_list = nexus_json_new_obj();

    if (key_list == NEXUS_JSON_INVALID_OBJ) {	
	log_error("Could not add JSON root object\n");
	return -1;
    }
    
    ret = nexus_json_add_array(key_list, "keys");

    if (ret == -1) {
	log_error("Could not add JSON key array\n");
	goto err;
    }
    
    ret = __save_volume_key_list(key_list);

    if (ret == -1) {
	goto err;
    }
    
    nexus_json_free(key_list);
    return 0;

 err:
    nexus_json_free(key_list);
    return -1;
}




int
nexus_get_volume_key(struct nexus_uuid * vol_uuid,
		     struct nexus_key  * key)
{
    nexus_json_obj_t key_list = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_json = __get_volume_key_list();

    char * vol_uuid_base64 = NULL;
    
    int num_keys = 0;
    int ret      = 0;
    int i        = 0;
    
    if (key_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not read volume key file\n");
	return -1;
    }

    key_list = nexus_json_get_array(key_json, "keys");

    if (key_list == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not find volume key list\n");
	return -1;
    }

    num_keys = nexus_json_get_array_len(key_list);


    log_debug("Found %d keys in volume key list\n", num_keys);
    
    if (num_keys == 0) {
	goto err;
    }

    vol_uuid_base64 = nexus_uuid_to_base64(vol_uuid);

    if (vol_uuid_base64 == NULL) {
	goto err;
	
    }
    
    for (i = 0; i < num_keys; i++) {
	char * key_uuid_base64 = NULL;
	char * key_base64      = NULL;
	
	nexus_json_obj_t key   = nexus_json_array_get_object(key_list, i);

	ret = nexus_json_get_string(key, "uuid", &key_uuid_base64);

	if (ret == -1) {
	    log_error("Malformed key entry in key list. Skipping\n");
	    continue;
	}

	if (strncmp(vol_uuid_base64, key_uuid_base64, strlen(vol_uuid_base64)) == 0) {
	    ret = nexus_json_get_string(key, "key", &key_base64);

	    if (ret == -1) {
		log_error("Corrupted key entry for Volume (%s): No key entry\n", vol_uuid_base64);
		goto err;
	    }

	    /* TODO: Grab the key type to pass to parser */
	    

	    ret = nexus_key_from_base64(key, key_base64);

	    if (ret == -1) {
		log_error("Corrupted key entry for Volume (%s): Invalid key format\n", vol_uuid_base64);
		goto err;		
	    }
	    
	    break;
	}
		      
    }
    
    nexus_free(vol_uuid_base64);
    nexus_json_free(key_json);

    return 0;

 err:

    if (vol_uuid_base64) nexus_free(vol_uuid_base64);
    
    nexus_json_free(key_json);

    return -1;    
}


int
nexus_add_volume_key(struct nexus_uuid * vol_uuid,
		     struct nexus_key  * key)
{
    nexus_json_obj_t new_key  = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_list = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_json = __get_volume_key_list();

    char * uuid_base64 = NULL;
    char * key_base64  = NULL;
    
    int ret = 0;

    if (key_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not read volume key file\n");
	return -1;
    }

    key_list = nexus_json_get_array(key_json, "keys");

    if (key_list == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not find volume key list\n");
	goto err;
    }

    new_key = nexus_json_array_add_object(key_list);

    if (new_key == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not create new key JSON object\n");
	goto err;
    }


    uuid_base64 = nexus_uuid_to_base64(vol_uuid);
    key_base64  = nexus_key_to_base64(key);

    if ( (uuid_base64 == NULL) ||
	 (key_base64  == NULL) ) {

	goto err;
    }
    
    ret |= nexus_json_add_string(new_key, "uuid", uuid_base64);
    ret |= nexus_json_add_string(new_key, "key",  key_base64);

    if (ret != 0) {
	log_error("Could not create JSON key object\n");
	goto err;
    }   

    ret = __save_volume_key_list(key_json);
    
    if (ret == -1) {
	log_error("Could not write Key list\n");
	goto err;
    }

    nexus_free(uuid_base64);
    nexus_free(key_base64);

    nexus_json_free(key_json);

    return -1;

 err:
    if (uuid_base64) nexus_free(uuid_base64);
    if (key_base64)  nexus_free(key_base64);
    
    nexus_json_free(key_json);
    return -1;
}





int
nexus_create_user_data()
{

    /* Create Volume Key list */
    __create_volume_key_list();


    /* Generate user public/private keys */


    return 0;
}
