/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


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

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_json.h>

#include "handler.h"

static const char * nexus_prog_version = "Nexus Admin Shell 0.1";



struct nexus_cmd {
    char * name;
    int (*handler)(int argc, char ** argv);   
    char * desc;
};


int
init_main(int argc, char ** argv)
{
    /* For now we just do a default config */
    nexus_setup();

    return 0;
}


extern int create_volume_main(int argc, char ** argv);

static struct nexus_cmd cmds[] = {
    {"init"   , init_main          , "Initialize Nexus state" },
    {"create" , create_volume_main , "Create a Nexus Volume"  },
    {0, 0, 0}
};


void
usage(void)
{
    int i = 0;

    printf("%s\n", nexus_prog_version);
    printf("Usage: nexus <command> [args...]\n");
    printf("Commands:\n");

    while (cmds[i].name) {
	printf("\t%-17s -- %s\n", cmds[i].name, cmds[i].desc);
	i++;
    }

    return;
    
}



int
main(int argc, char ** argv)
{
    int i   = 0;
    int ret = 0;

   if (argc < 2) {
	usage();
	exit(-1);
    }
    

    nexus_init();

    
    while (cmds[i].name) {

    	if (strncmp(cmds[i].name, argv[1], strlen(cmds[i].name)) == 0) {
	    ret = cmds[i].handler(argc - 1, &argv[1]);
	    break;
	}

	i++;
    }


    nexus_deinit();

    
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


    
    return ret;
}
