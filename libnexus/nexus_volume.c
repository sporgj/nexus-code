#include <nexus_volume.h>
#include <nexus_backend.h>
#include <nexus_datastore.h>
#include <nexus_config.h>
#include <nexus_user_data.h>

#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_util.h>

#define NEXUS_VOLUME_CONFIG_FILENAME ".nexus_volume.conf"





struct nexus_volume *
nexus_create_volume(char * volume_path,
		    char * config_str)
{
    struct nexus_volume * vol = NULL;
    
    nexus_json_obj_t vol_config;

    int ret = 0;
    
    // Check for config file, otherwise use default
    vol_config = nexus_json_parse_file(config_str);

    if (vol_config == NEXUS_JSON_INVALID_OBJ) {
	vol_config = nexus_json_parse_str(nexus_default_volume_config);
    }
    
    // Create Volume
    vol = calloc(sizeof(struct nexus_volume), 1);

    if (vol == NULL) {
	log_error("Could not allocate nexus volume\n");
	return NULL;
    }

    /* Init Volume */
    {
	nexus_uuid_gen(&(vol->vol_uuid));
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
	void             * meta_data_store      = NULL;
	nexus_json_obj_t   meta_data_store_cfg;
	char             * meta_data_store_name = NULL;
	
	meta_data_store_cfg = nexus_json_get_object(vol_config, "meta_data_store");

	if (meta_data_store_cfg == NEXUS_JSON_INVALID_OBJ) {
	    log_error("Invalid Config: Missing datastore config block\n");
	    goto err;
	}

	ret = nexus_json_get_string(meta_data_store_cfg, "name", &meta_data_store_name);

	if (ret == -1) {
	    log_error("Invalid Config: Missing datastore name\n");
	    goto err;
	}

	meta_data_store = nexus_datastore_create(meta_data_store_name, meta_data_store_cfg);
	
	if (meta_data_store == NULL) {
	    log_error("Could not create data store\n");
	    goto err;
	}

	vol->meta_data_store = meta_data_store;
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
	
	ret = nexus_backend_create_volume(vol->backend, vol);

	if (ret == -1) {
	    log_error("Backend Error: Could not create volume\n");
	    goto err;
	}
	
	uuid_str = nexus_uuid_to_base64(&vol->supernode_uuid);
	nexus_json_add_string(vol_config, "supernode_uuid", uuid_str);
	nexus_free(uuid_str);
    }

    /* Add volume key to list */
    {
	
    }
    
    /* Write config */
    {
	char * cfg_filename = NULL;

	ret = asprintf(&cfg_filename, "%s/%s", volume_path, NEXUS_VOLUME_CONFIG_FILENAME);

	if (ret == -1) {
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
    nexus_free(vol);
    return NULL;
}



struct nexus_volume *
nexus_load_volume(char * volume_path)
{

    struct nexus_volume  * volume  = NULL;
    struct nexus_backend * backend = NULL;
    
    nexus_json_obj_t volume_config = NEXUS_JSON_INVALID_OBJ;

    char   * conf_path      = NULL;	

    char   * supernode_str  = NULL;
    char   * volume_id_str  = NULL;
    char   * backend_str    = NULL;

    int ret = 0;

    volume = calloc(sizeof(struct nexus_volume), 1);

    if (volume == NULL) {
	log_error("Could not allocate Nexus Volume for (%s)\n", volume_path);
	goto err;
    }
    

    /*
     * Load JSON config file
     */
    ret = asprintf(&conf_path, "%s/%s", volume_path, NEXUS_VOLUME_CONFIG_FILENAME);
    
    if (ret == -1) {
	log_error("Could not create config path\n");
	goto err;
    }

    volume_config = nexus_json_parse_file(conf_path);

    if (ret == -1) {
	log_error("Failed to load Nexus Volume (%s)\n", volume_path);
	goto err;
    }
    
    nexus_free(conf_path);
    

    /* 
     * Initialize the backend 
     */
    ret = nexus_json_get_string(volume_config, "backend", &backend_str);

    if (ret  == -1) {
	log_error("Invalid volume configuration. Missing backend\n");
	goto err;
    }
    
    backend = nexus_backend_launch(backend_str, NULL);
    
    if (backend == NULL) {
	log_error("Could not initialize backend (%s)\n", backend_str);
	goto err;
    }


    /* 
     * parse volume UUID
     */
    ret = nexus_json_get_string(volume_config, "volume_id", &volume_id_str);

    log_debug("Volume_ID = %s\n", volume_id_str);

    // Generate UUID from volume ID
    

    /* 
     * parse Supernode UUID
     */
    ret = nexus_json_get_string(volume_config, "supernode_id", &supernode_str);
    
    log_debug("Supernode_ID=%s\n", supernode_str);

    // Generate UUID from string


    // Find the volume key using volume ID
    // __load_volume_key(volume->id);


    // backend_volume_open(volume->supernode_id, prvkey);

    
    
    return volume;

 err:

    if (backend)   nexus_backend_shutdown(backend);
    if (conf_path) nexus_free(conf_path);
    if (volume)    nexus_free(volume);
    

    
    return NULL;
}


void
nexus_close_volume(struct nexus_volume * volume)
{

    nexus_free(volume);
    return;
}
