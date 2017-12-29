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

static int cmd_line_user_key = 0;


static void usage()
{
    printf("ls: list directory entries for a given volume path\n\n"\
	   "Usage: ls <volume> <path-in-volume>\n");

    return;
}


int
ls_path_main(int argc, char ** argv)
{
    char * volume_path  = NULL;
    char * dir_path     = NULL;

    //    struct nexus_volume * vol = NULL;

  /* Override defaults with command line arguments */
    {
 	int  opt_index = 0;
	int  used_opts = 0;
	char c = 0;

	static struct option long_options[] = {
	    { "user_key"      , required_argument , &cmd_line_user_key ,  1  },  /* 0 */
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
	dir_path    = argv[used_opts + 2];
    }
    

    printf("Running 'ls' in volume (%s) for dir (%s)\n",
	   volume_path,
	   dir_path);
    

    nexus_mount_volume(volume_path);
    
    //    nexus_volume_ls(vol, dir_path);

    

    return 0;
    
}
