#include <nexus_volume.h>

#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>
#include <nexus_util.h>

#define NEXUS_VOLUME_CONFIG_FILENAME ".nexus_volume.conf"



struct nexus_volume *
nexus_load_volume(char * volume_path)
{
    struct nexus_volume * volume = NULL;

    char   * conf_path = NULL;	
    char   * conf_data = NULL;
    size_t   conf_size = 0;

    struct nexus_json_param vol_config[4] = { {"backend",      NEXUS_JSON_STRING, {0} },
					      {"metadata_url", NEXUS_JSON_STRING, {0} },
					      {"supernode",    NEXUS_JSON_STRING, {0} } };
    
    int ret = 0;

    ret = asprintf(&conf_path, "%s/%s", volume_path, NEXUS_VOLUME_CONFIG_FILENAME);

    if (ret == -1) {
	log_error("Could not create config path\n");
	return NULL;
    }
    
    ret = nexus_read_raw_file(conf_path, (uint8_t **)&conf_data, &conf_size);

    nexus_free(conf_path);
    
    if (ret == -1) {
	log_error("Failed to load Nexus Volume (%s)\n", volume_path);
	return NULL;
    }
    
    
    ret = nexus_json_parse((char *)conf_data, vol_config, 3);

    if (ret < 0) {
	log_error("Could not parse volume config file\n");
	goto err;
    }


    
    
    nexus_free(conf_data);
    nexus_json_release_params(vol_config, 3);
    
    return volume;

 err:
    if (conf_data) nexus_free(conf_data);

    nexus_json_release_params(vol_config, 3);

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
