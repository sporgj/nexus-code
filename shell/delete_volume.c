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


static void usage()
{
    printf("create: Deletes a Nexus volume\n\n"			\
	   "Usage: delete <volume-path> \n");
    return;
}




int
delete_volume_main(int argc, char ** argv)
{
    int ret = 0;
    

    if (argc > 2) {
	usage();
	return -1;
    }
    
    volume_path = argv[1];

    printf("Destroying Nexus Volume at (%s)\n", volume_path);
    
    ret = nexus_delete_volume(volume_path);

    if (ret == -1) {
	log_error("Could not delete volume at (%s)\n", volume_path);
	return -1;
    }

    return 0;

}
