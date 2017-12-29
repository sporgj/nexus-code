/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

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

    printf("key_file: %s\n", key_file_path);

    
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
    nexus_json_obj_t key_arr  = NEXUS_JSON_INVALID_OBJ;

    int ret = 0;
    
    key_list = nexus_json_new_obj("volume_key_list");

    if (key_list == NEXUS_JSON_INVALID_OBJ) {	
	log_error("Could not add JSON root object\n");
	return -1;
    }
    
    key_arr = nexus_json_add_array(key_list, "keys");

    if (key_arr == NEXUS_JSON_INVALID_OBJ) {
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
		     struct nexus_key  * vol_key)
{
    nexus_json_obj_t iter     = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_list = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_json = __get_volume_key_list();

    char * vol_uuid_alt64 = NULL;
    
    int ret      = 0;
    
    if (key_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not read volume key file\n");
	return -1;
    }

    key_list = nexus_json_get_array(key_json, "keys");

    if (key_list == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not find volume key list\n");
	return -1;
    }

    vol_uuid_alt64 = nexus_uuid_to_alt64(vol_uuid);

    if (vol_uuid_alt64 == NULL) {
	goto err;
	
    }
    
    nexus_json_arr_foreach(iter, key_list) {
	char * key_uuid_alt64 = NULL;
	char * key_str         = NULL;
	

	ret = nexus_json_get_string(iter, "uuid", &key_uuid_alt64);

	if (ret == -1) {
	    log_error("Malformed key entry in key list. Skipping\n");
	    continue;
	}

	if (strncmp(vol_uuid_alt64, key_uuid_alt64, strlen(vol_uuid_alt64)) == 0) {
	    nexus_key_type_t key_type = NEXUS_INVALID_KEY;
	    
	    char * type_str = NULL;
	    
	    ret |= nexus_json_get_string(iter, "key",  &key_str);
	    ret |= nexus_json_get_string(iter, "type", &type_str);

	    if (ret != 0) {
		log_error("Corrupted key entry for Volume (%s): No key entry\n", vol_uuid_alt64);
		goto err;
	    }

	    
	    key_type = nexus_key_type_from_str(type_str);

	    if (key_type == NEXUS_INVALID_KEY) {
		log_error("Tried to load invalid volume key type (%s)\n", type_str);
		goto err;
	    }
	    
	    ret = __nexus_key_from_str(vol_key, key_type, key_str);

	    if (ret == -1) {
		log_error("Could not load volume key (%s)\n", key_str);
		goto err;
	    }

	    break;
	}
		      
    }
    
    nexus_free(vol_uuid_alt64);
    nexus_json_free(key_json);

    return 0;

 err:

    if (vol_uuid_alt64) nexus_free(vol_uuid_alt64);
    
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

    char * uuid_alt64 = NULL;
    char * key_str  = NULL;
    
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


    uuid_alt64 = nexus_uuid_to_alt64(vol_uuid);
    key_str     = nexus_key_to_str(key);

    if ( (uuid_alt64 == NULL) ||
	 (key_str  == NULL) ) {

	goto err;
    }
    
    ret |= nexus_json_add_string(new_key, "uuid", uuid_alt64);
    ret |= nexus_json_add_string(new_key, "key",  key_str);

    if (ret != 0) {
	log_error("Could not create JSON key object\n");
	goto err;
    }   

    ret = __save_volume_key_list(key_json);
    
    if (ret == -1) {
	log_error("Could not write Key list\n");
	goto err;
    }

    nexus_free(uuid_alt64);
    nexus_free(key_str);

    nexus_json_free(key_json);

    return 0;

 err:
    if (uuid_alt64) nexus_free(uuid_alt64);
    if (key_str)  nexus_free(key_str);
    
    nexus_json_free(key_json);
    return -1;
}


int
nexus_del_volume_key(struct nexus_uuid * vol_uuid)
{
    nexus_json_obj_t iter     = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_list = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t key_json = __get_volume_key_list();

    char * vol_uuid_alt64 = nexus_uuid_to_alt64(vol_uuid);

    int ret = 0;
    
    if (key_json == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not parse volume key file\n");
	return -1;
    }

    key_list = nexus_json_get_array(key_json, "keys");

    if (key_list == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not find volume key list\n");
	goto err;
    }

    
    nexus_json_arr_foreach(iter, key_list) {
	char * iter_uuid_alt64 = NULL;
	
	ret = nexus_json_get_string(iter, "uuid", &iter_uuid_alt64);

	if (ret == -1) {
	    log_error("Corrupt volume key list\n");
	    goto err;
	}

	if (strncmp(vol_uuid_alt64, iter_uuid_alt64, strlen(vol_uuid_alt64)) == 0) {
	    
	    nexus_json_array_del_item(key_list, iter);
	}
    }
    

    ret = __save_volume_key_list(key_json);
    
    if (ret == -1) {
	log_error("Could not write Key list\n");
	goto err;
    }
    

    nexus_json_free(key_json);
    nexus_free(vol_uuid_alt64);

    return 0;

 err:
    if (vol_uuid_alt64) nexus_free(vol_uuid_alt64);
    nexus_json_free(key_json);
    
    return -1;
}


struct nexus_key * 
nexus_get_user_key()
{
    struct nexus_key * user_key = NULL;

    user_key = nexus_key_from_file(NEXUS_MBEDTLS_PRV_KEY, nexus_config.user_key_path);

    if (user_key == NULL) {
	log_error("Could not retrieve nexus user key from file (%s)\n", nexus_config.user_key_path);
    }    

    return user_key;
}


int
nexus_user_dir_exists()
{
    DIR * user_dir = NULL;

    user_dir = opendir(nexus_config.user_data_dir);

    if (user_dir) {
	closedir(user_dir);
	return 1;
    }

    return 0;
}



int
nexus_create_user_data()
{
    int ret = 0;
    
    if (nexus_user_dir_exists()) {
	nexus_printf("User directory already exists\n");
	return -1;
    }
    
    /* Make user data directory */
    nexus_printf("Creating Nexus user directory (%s)\n", nexus_config.user_data_dir);
    
    ret = mkdir(nexus_config.user_data_dir, 0700);

    if (ret == -1) {
	log_error("Could not create user data directory at (%s)\n", nexus_config.user_data_dir);
	return -1;
    }


    /* Create Volume Key list */
    nexus_printf("Creating Volume key list\n");

    ret = __create_volume_key_list();

    if (ret == -1) {
	log_error("Could not create volume key file at (%s/%s)\n",
		  nexus_config.user_data_dir,
		  NEXUS_VOLUME_KEY_FILENAME);
	return -1;
    }
    
	
    /* Generate user private key */
    nexus_printf("Generating User Key (This may take a little while)\n");
    
    {
	struct nexus_key * user_key = NULL;
	
	user_key = nexus_create_key(NEXUS_MBEDTLS_PRV_KEY);

	if (user_key == NULL) {
	    log_error("Could not create user key\n");
	    return -1;
	}
	
	ret = nexus_key_to_file(user_key, nexus_config.user_key_path);	

	if (ret == -1) {
	    log_error("Could not save user key to file (%s)\n", nexus_config.user_key_path);
	    return -1;
	}
    }

    return 0;
}
