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


struct nexus_volume *
nexus_load_volume(char * volume_path);


void
nexus_close_volume(struct nexus_volume * volume);



/* JRL: This might be a bit much...
 *      We can probably just pass the correct datastore directly to the datastore API
 */

#if 0
int
nexus_vol_set_metadata_uuid(struct nexus_volume * volume,
			    struct nexus_uuid   * uuid,
			    char                * path,
			    uint8_t             * buf,
			    uint32t               size);

int
nexus_vol_add_metadata_uuid(struct nexus_volume * volume,
			    struct nexus_uuid   * uuid,
			    char                * path,
			    uint8_t             * buf,
			    uint32t               size);

int
nexus_vol_get_metadata_uuid(struct nexus_volume * volume,
			    struct nexus_uuid   * uuid,
			    char                * path,
			    uint8_t            ** buf,
			    uint32t             * size);

int
nexus_vol_del_metadata_uuid(struct nexus_volume * volume,
			    struct nexus_uuid   * uuid,
			    char                * path);



int
nexus_vol_set_data_uuid(struct nexus_volume * volume,
			struct nexus_uuid   * uuid,
			char                * path,
			uint8_t             * buf,
			uint32t               size);

int
nexus_vol_add_data_uuid(struct nexus_volume * volume,
			struct nexus_uuid   * uuid,
			char                * path,
			uint8_t             * buf,
			uint32t               size);

int
nexus_vol_get_data_uuid(struct nexus_volume * volume,
			struct nexus_uuid   * uuid,
			char                * path,
			uint8_t            ** buf,
			uint32t             * size);
int
nexus_vol_del_data_uuid(struct nexus_volume * volume,
			struct nexus_uuid   * uuid,
			char                * path);


#endif
