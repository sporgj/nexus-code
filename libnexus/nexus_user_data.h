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


int nexus_create_user_data();


int
nexus_add_volume_key(struct nexus_uuid * vol_uuid,
		     struct nexus_key  * key);


int
nexus_get_volume_key(struct nexus_uuid * vol_uuid,
		     struct nexus_key  * key);


struct nexus_key * nexus_get_user_key();
