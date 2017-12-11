#pragma once

#include <nexus_key.h>


struct nexus_volume {
    char * volume_path;


    struct nexus_backend * backend;

    // struct supernode    * supernode;
    //struct nexus_dentry * root_dentry;

    void * private_data;
};



struct nexus_volume *
nexus_load_volume(char * volume_path);


void
nexus_close_volume(struct nexus_volume * volume);
