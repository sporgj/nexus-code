/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <nexus_key.h>
#include <nexus_uuid.h>
#include <nexus_datastore.h>
#include <nexus_backend.h>

struct nexus_volume {
    char * volume_path;

    struct nexus_key vol_key;
    
    struct nexus_uuid vol_uuid;
    struct nexus_uuid supernode_uuid;
    
    struct nexus_backend   * backend;
    struct nexus_datastore * data_store;
    struct nexus_datastore * metadata_store;
    
    void * private_data;
};



struct nexus_volume *
nexus_create_volume(char * volume_path,
                    char * config_str);


int
nexus_delete_volume(char * volume_path);

struct nexus_volume *
nexus_mount_volume(char * volume_path);


void
nexus_close_volume(struct nexus_volume * volume);

