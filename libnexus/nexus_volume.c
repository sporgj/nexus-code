#include <nexus_volume.h>

#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_util.h>

#define NEXUS_VOLUME_CONFIG_FILENAME ".nexus_volume.conf"



struct nexus_volume *
nexus_load_volume(char * volume_path)
{

    struct nexus_volume * volume       = NULL;
    nexus_json_obj_t      nexus_config = NEXUS_JSON_INVALID_OBJ;

    char   * conf_path = NULL;	
    char   * supernode = NULL;
    
    int ret = 0;

    ret = asprintf(&conf_path, "%s/%s", volume_path, NEXUS_VOLUME_CONFIG_FILENAME);
    
    if (ret == -1) {
	log_error("Could not create config path\n");
	return NULL;
    }

    // Load JSON config params
    nexus_config = nexus_json_parse_file(conf_path);

    nexus_free(conf_path);
    
    if (ret == -1) {
	log_error("Failed to load Nexus Volume (%s)\n", volume_path);
	goto err;
    }
    
    supernode = nexus_json_get_string(nexus_config, "supernode");
    

    log_error("Supernode=%s\n", supernode);
    
    return volume;

 err:

    if (volume) nexus_free(volume);

    return NULL;
}


void
nexus_close_volume(struct nexus_volume * volume)
{
    nexus_free(volume->volume_path);
    nexus_free(volume->metadata_path);
    nexus_free(volume->data_path);

    nexus_free_key(volume->volume_key);

    nexus_free(volume);
    
    return;
}
