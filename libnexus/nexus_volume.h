#pragma once

#include <nexus_key.h>
#include <nexus_uuid.h>
#include <nexus_datastore.h>
#include <nexus_backend.h>

struct nexus_volume {
    char * volume_path;

    struct nexus_uuid vol_uuid;
    struct nexus_uuid supernode_uuid;

    struct nexus_key  vol_key;
    
    struct nexus_backend   * backend;
    struct nexus_datastore * data_store;
    struct nexus_datastore * meta_data_store;
    
    void * private_data;
};



struct nexus_volume *
nexus_load_volume(char * volume_path);


void
nexus_close_volume(struct nexus_volume * volume);
