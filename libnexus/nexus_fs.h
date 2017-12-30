/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>
#include <unistd.h>


#include <linux/limits.h>

struct nexus_volume;

/* 
 *  These are probably just going to be passthrough functions...
 */

typedef enum {
    NEXUS_REG = 1,  /* regular file */
    NEXUS_DIR = 2,  /* directory    */
    NEXUS_LNK = 3   /* symlink      */
} nexus_dirent_type_t;


struct nexus_dirent {
    char                name[NAME_MAX];
    nexus_dirent_type_t type;
};

struct nexus_stat {
    char name[NAME_MAX];
    char path[PATH_MAX];

    nexus_dirent_type_t type;
    size_t              size;
    
};



int
nexus_fs_readdir(struct nexus_volume *  volume,
		 char                *  path,
		 struct nexus_dirent ** result);


int
nexus_fs_stat(struct nexus_volume * volume,
	      char                * path,
	      struct nexus_stat   * stat);


int
nexus_fs_delete(struct nexus_volume * volume,
		char                * path);


int
nexus_fs_create(struct nexus_volume * volume,
		char                * path,
		nexus_dirent_type_t   type,
		struct nexus_stat   * stat);



int
nexus_fs_encrypt(struct nexus_volume * volume,
		 char                * path,
		 uint8_t             * in_buf,
		 uint8_t             * out_buf,
		 off_t                 offset,
		 size_t                size);


int
nexus_fs_decrypt(struct nexus_volume * volume,
		 char                * path,
		 uint8_t             * in_buf,		 
		 uint8_t             * out_buf,
		 off_t                 offset,
		 size_t                size);
