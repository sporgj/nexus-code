/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#pragma once



struct nexus_config {
    char * user_data_dir;
    
    char * user_prv_key_path;
    char * user_pub_key_path;

    char * volume_config;
};


extern struct nexus_config nexus_config;
extern char * nexus_default_volume_config;


int nexus_config_init(void);
