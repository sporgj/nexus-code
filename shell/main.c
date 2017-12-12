#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include <wordexp.h>

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_json.h>

#include "handler.h"



#define DEFAULT_VOLUME_PATH       "$HOME/nexus-volume"

#define DEFAULT_VOL_KEY_FILENAME  "$HOME/.nexus/volume_key"
#define DEFAULT_PUB_KEY_FILENAME  "$HOME/.nexus/public_key"
#define DEFAULT_PRV_KEY_FILENAME  "$HOME/.nexus/private_key"


static char * volume_path          = NULL;

static char * vol_key_filename     = NULL;
static char * pub_key_filename     = NULL;
static char * prv_key_filename     = NULL;

static int cmd_line_vol_path       = 0;
static int cmd_line_prv_key        = 0;
static int cmd_line_pub_key        = 0;
static int cmd_line_vol_key        = 0;

static int 
set_defaults()
{
    wordexp_t volume_path_exp;
    wordexp_t vol_key_filename_exp;
    wordexp_t pub_key_filename_exp;
    wordexp_t prv_key_filename_exp;

    wordexp(DEFAULT_VOLUME_PATH,      &volume_path_exp,      0);
    wordexp(DEFAULT_VOL_KEY_FILENAME, &vol_key_filename_exp, 0);
    wordexp(DEFAULT_PUB_KEY_FILENAME, &pub_key_filename_exp, 0);
    wordexp(DEFAULT_PRV_KEY_FILENAME, &prv_key_filename_exp, 0);

    
    volume_path        = strndup(volume_path_exp.we_wordv[0],      PATH_MAX);
    vol_key_filename   = strndup(vol_key_filename_exp.we_wordv[0], PATH_MAX);
    pub_key_filename   = strndup(pub_key_filename_exp.we_wordv[0], PATH_MAX);
    prv_key_filename   = strndup(prv_key_filename_exp.we_wordv[0], PATH_MAX);

    wordfree(&volume_path_exp);
    wordfree(&vol_key_filename_exp);
    wordfree(&pub_key_filename_exp);
    wordfree(&prv_key_filename_exp);

    return 0;
}






void
usage(void)
{
    printf("Usage: \n");
    return;
}

static struct option long_options[] = {
    { "volume"       , required_argument , &cmd_line_vol_path       ,  1  }, /* 1 */
    { "prv_key"      , required_argument , &cmd_line_prv_key        ,  1  }, /* 2 */
    { "pub_key"      , required_argument , &cmd_line_pub_key        ,  1  }, /* 3 */
    { "vol_key"      , required_argument , &cmd_line_vol_key        ,  1  }, /* 4 */
    { "help"         , no_argument       , 0                        , 'h' },
    { 0, 0, 0, 0 }
};

int
main(int argc, char ** argv)
{

    /* Setup default path strings with ENV expansions */
    set_defaults();

    
    /* Override defaults with command line arguments */
    {
 	int  opt_index = 0;
	char c = 0;
	
	
	while ((c = getopt_long(argc, argv, "h", long_options, &opt_index)) != -1) {
	    
	    switch (c) {
		case 0:
		    switch (opt_index) {
			case 0:
			    nexus_free(volume_path);
			    volume_path = optarg;
			    break;

			case 1:
			    nexus_free(prv_key_filename);
			    prv_key_filename = optarg;
			    break;

			case 2:
			    nexus_free(pub_key_filename);
			    pub_key_filename = optarg;
			    break;

			case 3:
			    nexus_free(vol_key_filename);
			    vol_key_filename = optarg;
			    break;
			default:
			    break;
		    }
		    break;

		case 'h':
		default:
		    usage();
		    return -1;
	    }
	}
    }
    

    nexus_init();
    
    printf("Launching Nexus Shell.\n");

    printf("Volume : %s\n", volume_path);


    {	
	char * json_file = NULL;
	char * out_str   = NULL;
	nexus_json_obj_t obj = NEXUS_JSON_INVALID_OBJ;
	
	asprintf(&json_file, "%s/config.json", volume_path);

	obj = nexus_json_parse_file(json_file);

	
	out_str = nexus_json_serialize(obj);
	printf("Serialized: (%s)\n", out_str);
	free(out_str);

	nexus_json_obj_t tmp_obj = nexus_json_get_object(obj, "web-app");	

	if (tmp_obj == NULL) {
	    printf("ERROR Could not find servlet-mapping\n");
	    return -1;
	}
	      

	tmp_obj = nexus_json_get_object(tmp_obj, "servlet-mapping");
	
	nexus_json_set_string(tmp_obj, "cofaxAdmin", "jarusl");
	nexus_json_add_u16(tmp_obj, "test short", 9991);
	
	
	out_str = nexus_json_serialize(obj);
	printf("Serialized: (%s)\n", out_str);
	free(out_str);

	
	
    }
    
#if 0

       // initialize libnexus and mount the volume
    {
	int ret = -1;

        ret = nexus_mount_volume(volume_path,
				 vol_key_filename,
				 pub_key_filename,
				 prv_key_filename);
	if (ret != 0) {
	    log_error("could not mount volume\n");
	    return -1;
	}
    }
#endif


    
    return 0;
}
