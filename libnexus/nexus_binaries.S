/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

.data
	
.globl nexus_default_vol_cfg_start
nexus_default_vol_cfg_start:
.incbin "nexus_default_volume_config.json"
.global nexus_default_vol_cfg_end
nexus_default_vol_cfg_end:

