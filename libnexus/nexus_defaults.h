/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#pragma once




struct nexus_defaults {
    char * volume_path;
    
    char * volume_key_path;

    char * user_prv_key_path;
    char * user_pub_key_path;
};


extern struct nexus_defaults nexus_defaults;


int nexus_defaults_init(void);
