/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <sys/stat.h>

#include <nexus_volume.h>
#include <nexus_backend.h>
#include <nexus_datastore.h>
#include <nexus_user_data.h>

#include <nexus_key.h>

#include <nexus_util.h>
#include <nexus_log.h>



int
nexus_init()
{

    printf("Initializing Nexus\n");

    nexus_config_init();
    nexus_backend_init();
    nexus_datastores_init();

    return 0;
}


int
nexus_deinit()
{
    printf("Deinitializing Nexus\n");
    return 0;
}

int
nexus_setup()
{
    return nexus_create_user_data();
}
