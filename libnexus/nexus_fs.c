/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_fs.h>
#include <nexus_backend.h>

#include <nexus_util.h>
#include <nexus_log.h>


int
nexus_fs_readdir(struct nexus_volume *  volume,
		 char                *  path,
		 struct nexus_dirent ** result)
{

    return -1;
}


int
nexus_fs_create(struct nexus_volume * volume,
		char                * path,
		nexus_dirent_type_t   type,
		struct nexus_stat   * stat)
{
    return nexus_backend_fs_create(volume, path, type, stat);
}
