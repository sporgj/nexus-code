/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_config.h>
#include <nexus_volume.h>

static char * volume_path   = NULL;


static int cmd_line_user_key    = 0;
static int cmd_line_config_file = 0;


static void
__set_defaults()
{
    nexus_config.user_volconfig_path = NULL;
}

static void usage()
{
    printf("create: Creates a Nexus volume\n\n"			\
	   "Usage: create <volume-path> [options]\n"		\
	   " Options: \n");

    printf("\t[--user_key]   (default: %-*s)       : Location of User's public key\n",
	   32, nexus_config.user_key_path);

    // this is hardcoded in libnexus/nexus_binaries.S
    printf("\t  [--config]   "
           "(default:libnexus/nexus_default_volume_config.json)\n");

    return;
}




int
create_volume_main(int argc, char ** argv)
{
    struct nexus_volume * vol = NULL;

    __set_defaults();
    
    /* Override defaults with command line arguments */
    {
 	int  opt_index = 0;
	int  used_opts = 0;
	char c = 0;

	static struct option long_options[] = {
	    { "user_key"      , required_argument , &cmd_line_user_key ,  1  },  /* 0 */
	    { "config"      , required_argument , &cmd_line_config_file ,  1  },  /* 1 */
	    { 0, 0, 0, 0 }
	};
	
	
	while ((c = getopt_long_only(argc, argv, "h", long_options, &opt_index)) != -1) {	    

	    switch (c) {
		case 0:
		    switch (opt_index) {
			case 0:
			    nexus_config.user_key_path = optarg;
			    used_opts += 2;
			    break;

			case 1:
			    nexus_config.user_volconfig_path = optarg;
			    used_opts += 2;
			    break;
			    

			default:
			    usage();
			    return -1;
		    }
		    break;
		case 'h':
		case '?':
		default:
		    usage();
		    return -1;
	    }
	}

		
	/* At this point we should just have the volume path in ARGV */

	if (argc - used_opts != 2) {
	    usage();
	    return -1;
	}


	volume_path = argv[used_opts + 1];
    }


    printf("Creating Nexus Volume at (%s)\n", volume_path);
    
    vol = nexus_create_volume(volume_path, nexus_config.user_volconfig_path);

    if (vol == NULL) {
	log_error("Could not create volume at (%s)\n", volume_path);
	return -1;
    }

    return 0;

}
