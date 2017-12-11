#include <nexus_volume.h>
#include <nexus_backend.h>

#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_util.h>

#define NEXUS_VOLUME_CONFIG_FILENAME ".nexus_volume.conf"

struct nexus_volume *
nexus_create_volume(char * volume_path)
{
    // Create Volume key

    // Create supernode from backend

    // Write config file

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
    backend_str = nexus_json_get_string(volume_config, "backend");

    if (backend_str == NULL) {
	log_error("Invalid volume configuration. Missing backend\n");
	goto err;
    }
    
    backend = nexus_backend_launch(backend_str);
    
    if (backend == NULL) {
	log_error("Could not initialize backend (%s)\n", backend_str);
	goto err;
    }


    /* 
     * parse volume UUID
     */
    volume_id_str = nexus_json_get_string(volume_config, "volume_id");

    log_debug("Volume_ID = %s\n", volume_id_str);

    // Generate UUID from volume ID
    

    /* 
     * parse Supernode UUID
     */
    supernode_str = nexus_json_get_string(volume_config, "supernode_id");
    
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
