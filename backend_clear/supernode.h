/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once
#include <stdint.h>

#include <nexus_uuid.h>
#include <nexus_key.h>

struct nexus_volume;

int
create_supernode(struct nexus_volume * volume,
		 struct nexus_key    * user_pub_key,
		 struct nexus_uuid   * supernode_uuid,
		 struct nexus_key    * volume_key);
