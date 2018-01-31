/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <unistd.h>

#include <nexus_volume.h>
#include <nexus_backend.h>
#include <nexus_datastore.h>
#include <nexus_config.h>
#include <nexus_user_data.h>

#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_raw_file.h>

#define NEXUS_VOLUME_CONFIG_FILENAME ".nexus_volume.conf"

static char *
__get_volume_config_path(char * volume_path)
{
    char * cfg_filename = NULL;
    int    ret          = 0;
    
    ret = asprintf(&cfg_filename, "%s/%s", volume_path, NEXUS_VOLUME_CONFIG_FILENAME);
    
    if (ret == -1) {
	log_error("Could not allocate cfg_filename\n");
	return NULL;
    }

    return cfg_filename;
}
    

static nexus_json_obj_t
__get_volume_config(char * volume_path)
{
    nexus_json_obj_t   cfg_json = NEXUS_JSON_INVALID_OBJ;
    char             * cfg_file = NULL;
    
    cfg_file = __get_volume_config_path(volume_path);

    if (cfg_file == NULL) {
	log_error("Could not allocate config path string\n");
	return NEXUS_JSON_INVALID_OBJ;
    }

    cfg_json = nexus_json_parse_file(cfg_file);
    
    nexus_free(cfg_file);

    return cfg_json;   
}


struct nexus_volume *
nexus_create_volume(char * volume_path,
		    char * config_str)
{
    struct nexus_volume * vol = NULL;

    char * temp_cwd = NULL;
    
    nexus_json_obj_t vol_config;

    int ret = 0;
    
    // Check for config file, otherwise use default

    if (config_str) {
	vol_config = nexus_json_parse_file(config_str);
    } else {
	vol_config = nexus_json_parse_str(nexus_default_volume_config);
    }

    if (vol_config == NEXUS_JSON_INVALID_OBJ) {
	log_error("Could not parse Volume config\n");
	return NULL;
    }
    
    // Create Volume
    vol = nexus_malloc(sizeof(struct nexus_volume));

    
    /* Init Volume uuid */
    {
	char * uuid_alt64 = NULL;

	nexus_uuid_gen(&(vol->vol_uuid));

	uuid_alt64 = nexus_uuid_to_alt64(&(vol->vol_uuid));

	nexus_json_add_string(vol_config, "volume_uuid", uuid_alt64);

	nexus_free(uuid_alt64);
    }

    temp_cwd = get_current_dir_name();
    if (temp_cwd == NULL) {
	log_error("get_current_dir_name() FAILED (err=%s)\n", strerror(errno));
	return NULL;
    }

    ret = chdir(volume_path);

    if (ret == -1) {
	log_error("Could not chdir to (%s)\n", volume_path);
	goto err;
    }

    /* Setup Data store */
    {
	void             * data_store      = NULL;
	nexus_json_obj_t   data_store_cfg;
	char             * data_store_name = NULL;
	
	data_store_cfg = nexus_json_get_object(vol_config, "data_store");

	if (data_store_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid Config: Missing datastore config block\n");
	    goto err;
	}

	ret = nexus_json_get_string(data_store_cfg, "name", &data_store_name);

	if (ret == -1) {
	    log_error("Invalid Config: Missing datastore name\n");
	    goto err;
	}

	data_store = nexus_datastore_create(data_store_name, data_store_cfg);
	
	if (data_store == NULL) {
	    log_error("Could not create data store\n");
	    goto err;
	}

	vol->data_store = data_store;
    }

    /* Setup Metadata Store */
    {
	void             * metadata_store      = NULL;
	nexus_json_obj_t   metadata_store_cfg;
	char             * metadata_store_name = NULL;
	
	metadata_store_cfg = nexus_json_get_object(vol_config, "metadata_store");

	if (metadata_store_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid Config: Missing metadata_store config block\n");
	    goto err;
	}

	ret = nexus_json_get_string(metadata_store_cfg, "name", &metadata_store_name);

	if (ret == -1) {
	    log_error("Invalid Config: Missing datastore name\n");
	    goto err;
	}

	metadata_store = nexus_datastore_create(metadata_store_name, metadata_store_cfg);
	
	if (metadata_store == NULL) {
	    log_error("Could not create data store\n");
	    goto err;
	}

	vol->metadata_store = metadata_store;
    }

    /* Setup Backend */
    {
	void             * backend      = NULL;
	nexus_json_obj_t   backend_cfg;
	char             * backend_name = NULL;
	
	backend_cfg = nexus_json_get_object(vol_config, "backend");

	if (backend_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid Config: Missing datastore config block\n");
	    goto err;
	}

	ret = nexus_json_get_string(backend_cfg, "name", &backend_name);
	
	if (ret == -1) {
	    log_error("Invalid Config: Missing datastore name\n");
	    goto err;
	}

	backend = nexus_backend_launch(backend_name, backend_cfg);
	
	if (backend == NULL) {
	    log_error("Could not create data store\n");
	    goto err;
	}

	vol->backend = backend;
    }

    /* Create supernode from backend */
    {
	char * uuid_str = NULL;
	
	ret = nexus_backend_init_volume(vol);

	if (ret == -1) {
	    log_error("Backend Error: Could not create volume\n");
	    goto err;
	}
	
	uuid_str = nexus_uuid_to_alt64(&vol->supernode_uuid);
	nexus_json_add_string(vol_config, "supernode_uuid", uuid_str);
	nexus_free(uuid_str);
    }

    /* Add volume key to list if it exists */
    
    if (nexus_get_key_type(&(vol->vol_key)) != NEXUS_INVALID_KEY) {
	
	ret = nexus_add_volume_key(&(vol->vol_uuid), &(vol->vol_key));

	if (ret == -1) {
	    log_error("Could not add volume key to key list\n");
	    goto err;
	}
    }
    
    // restore the current directory
    ret = chdir(temp_cwd);

    if (ret == -1) {
	log_error("Could not chdir to (%s)\n", temp_cwd);
	goto err;
    }

    /* Write config */
    {
	char * cfg_filename = NULL;

	cfg_filename = __get_volume_config_path(volume_path);

	if (cfg_filename == NULL) {
	    log_error("Could not allocate cfg_filename\n");
	    goto err;
	}
	
	ret = nexus_json_serialize_to_file(vol_config, cfg_filename);
	nexus_free(cfg_filename);

	if (ret == -1) {
	    log_error("Could not write volume config file\n");
	    goto err;
	}
	
    }
    return vol;

err:

    /* TODO: 
     *  Lots of free/deinits need to happen here....
     */
    if (temp_cwd) {
	chdir(temp_cwd);

	nexus_free(temp_cwd);
    }

    nexus_free(vol);
    return NULL;
}



int
nexus_delete_volume(char * volume_path)
{
    nexus_json_obj_t vol_cfg = NEXUS_JSON_INVALID_OBJ;

    int ret = 0;


    /* Change to volume dir */
    {
	ret = chdir(volume_path);
	
	if (ret == -1) {
	    log_error("Could not chdir to (%s)\n", volume_path);
	    goto err;
	}
    }
    

    /*
     * Load JSON config file
     */
    {
	vol_cfg = __get_volume_config(volume_path);
	
	if (vol_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Could not get volume config\n");
	    goto err;
	}
    }
    

    /* blow away data */
    {
	nexus_json_obj_t   data_cfg  = NEXUS_JSON_INVALID_OBJ;
	char             * data_name = NULL;

	data_cfg = nexus_json_get_object(vol_cfg, "data_store");
	
	if (data_cfg  == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid volume configuration. Missing data config\n");
	    goto err;
	}

	ret = nexus_json_get_string(data_cfg, "name", &data_name);

	if (ret == -1) {
	    log_error("Invalid volume configuration. Missing data name\n");
	    goto err;
	}
        	
	ret = nexus_datastore_delete(data_name, data_cfg);
	
	if (ret == -1) {
	    log_error("Could not delete data_store (%s)\n", data_name);
	}
    }
    

    /* blow away metadata */
    {
	nexus_json_obj_t   metadata_cfg  = NEXUS_JSON_INVALID_OBJ;
	char             * metadata_name = NULL;
	
	metadata_cfg = nexus_json_get_object(vol_cfg, "metadata_store");
	
	if (metadata_cfg  == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid volume configuration. Missing metadata config\n");
	    goto err;
	}

	ret = nexus_json_get_string(metadata_cfg, "name", &metadata_name);

	if (ret == -1) {
	    log_error("Invalid volume configuration. Missing metadata name\n");
	    goto err;
	}
        	
	ret = nexus_datastore_delete(metadata_name, metadata_cfg);
	
	if (ret == -1) {
	    log_error("Could not delete metadata_store (%s)\n", metadata_name);
	}
    }
    
    
    /* Remove volume id/key from volume list */
    {
	struct nexus_uuid   vol_uuid;
	char              * uuid_str = NULL;
	
	ret = nexus_json_get_string(vol_cfg, "volume_uuid", &uuid_str);

	if (ret == -1) {
	    log_error("Invalid volume config. Missing volume uuid\n");
	    goto err;
	}

	nexus_uuid_from_alt64(&vol_uuid, uuid_str);
	
	nexus_del_volume_key(&vol_uuid);
    }
    
    
    /* delete volume config file */
    {
	char * cfg_filename = NULL;

	cfg_filename = __get_volume_config_path(volume_path);

	if (cfg_filename == NULL) {
	    log_error("could not get config path\n");
	    goto err;
	}
	
	ret = nexus_delete_raw_file(cfg_filename);

	nexus_free(cfg_filename);

	if (ret == -1) {
	    log_error("Could not delete volume config file\n");
	    goto err;
	}
    }

    
    nexus_json_free(vol_cfg);
    
    return 0;
 err:
    
    if (vol_cfg != NEXUS_JSON_INVALID_OBJ) nexus_json_free(vol_cfg);
    
    return -1;
}



struct nexus_volume *
nexus_mount_volume(char * volume_path)
{

    struct nexus_volume  * volume  = NULL;
    struct nexus_backend * backend = NULL;
    
    nexus_json_obj_t vol_cfg = NEXUS_JSON_INVALID_OBJ;


    int ret = 0;

    volume = nexus_malloc(sizeof(struct nexus_volume));

    /*
     * Load JSON config file
     */
    {
	vol_cfg = __get_volume_config(volume_path);
	
	if (vol_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Could not get volume config\n");
	    goto err;
	}
    }
    
    /* 
     * parse volume UUID and get the volume key 
     */
    {
	char   * volume_id_str  = NULL;

	ret = nexus_json_get_string(vol_cfg, "volume_uuid", &volume_id_str);
	
	if (ret == -1) {
	    log_error("Invalid volume configuration (missing volume_id)\n");
	    goto err;
	}
	
	log_debug("Volume_ID = %s\n", volume_id_str);
	
	/* parse volume ID */
	nexus_uuid_from_alt64(&(volume->vol_uuid), volume_id_str);


	/* Fetch the volume key */
	ret = nexus_get_volume_key(&(volume->vol_uuid), &(volume->vol_key));
	
	if (ret == -1) {
	    log_error("Could not find volume key for volume (%s)\n", volume_id_str);
	    goto err;
	}
    }

    ret = chdir(volume_path);

    if (ret == -1) {
	log_error("Could not chdir to (%s)\n", volume_path);
	goto err;
    }
    

    /* 
     * Initialize the metadata store 
     */
    {
	nexus_json_obj_t   metadata_cfg  = NEXUS_JSON_INVALID_OBJ;
	char             * metadata_name = NULL;
	
	metadata_cfg = nexus_json_get_object(vol_cfg, "metadata_store");
	
	if (metadata_cfg  == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid volume configuration. Missing metadata config\n");
	    goto err;
	}

	ret = nexus_json_get_string(metadata_cfg, "name", &metadata_name);

	if (ret == -1) {
	    log_error("Invalid volume configuration. Missing metadata name\n");
	    goto err;
	}
        	
	volume->metadata_store = nexus_datastore_open(metadata_name, metadata_cfg);
	
	if (volume->metadata_store == NULL) {
	    log_error("Could not initialize metadata_store (%s)\n", metadata_name);
	    goto err;
	}
    }

    /* 
     * Initialize the data store 
     */
    {
	nexus_json_obj_t   data_cfg  = NEXUS_JSON_INVALID_OBJ;
	char             * data_name = NULL;
	
	data_cfg = nexus_json_get_object(vol_cfg, "data_store");
	
	if (data_cfg  == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid volume configuration. Missing data config\n");
	    goto err;
	}

	ret = nexus_json_get_string(data_cfg, "name", &data_name);

	if (ret == -1) {
	    log_error("Invalid volume configuration. Missing data name\n");
	    goto err;
	}
        	
	volume->data_store = nexus_datastore_open(data_name, data_cfg);
	
	if (volume->data_store == NULL) {
	    log_error("Could not initialize data_store (%s)\n", data_name);
	    goto err;
	}


    }
   
    
    
    /* 
     * Initialize the backend 
     */
    {
	nexus_json_obj_t   backend_cfg  = NEXUS_JSON_INVALID_OBJ;
	char             * backend_name = NULL;
	
	backend_cfg = nexus_json_get_object(vol_cfg, "backend");
	
	if (backend_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid volume configuration. Missing backend configuration\n");
	    goto err;
	}

	ret = nexus_json_get_string(backend_cfg, "name", &backend_name);

	if (ret == -1) {
	    log_error("Invalid volume configuration. Missing backend name\n");
	    goto err;
	}
	
	volume->backend = nexus_backend_launch(backend_name, backend_cfg);
	
	if (volume->backend == NULL) {
	    log_error("Could not initialize backend (%s)\n", backend_name);
	    goto err;
	}

    }

    

    /* 
     * parse Supernode UUID
     */
    {
	char * supernode_str  = NULL;

	ret = nexus_json_get_string(vol_cfg, "supernode_uuid", &supernode_str);

	if (ret == -1) {
	    log_error("Invalid volume configuration. Missing Supernode UUID\n");
	    goto err;
	}
	
	log_debug("Supernode_UUID=%s\n", supernode_str);
	
	// Generate UUID from string
	nexus_uuid_from_alt64(&(volume->supernode_uuid), supernode_str);
    }


    
    ret = nexus_backend_open_volume(volume);

    if (ret == -1) {
	log_error("Could not open volume (backend error)\n");
	goto err;
    }
    
    return volume;

 err:

    if (backend)   nexus_backend_shutdown(backend);
    if (volume)    nexus_free(volume);
    

    
    return NULL;
}


void
nexus_close_volume(struct nexus_volume * volume)
{

    nexus_free(volume);
    return;
}
