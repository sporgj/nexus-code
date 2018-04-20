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


typedef enum {
    NEXUS_FREAD          = 0x00000001,
    NEXUS_FWRITE         = 0x00000002,
    NEXUS_FRDWR          = NEXUS_FREAD | NEXUS_FWRITE,

    NEXUS_FDELETE        = 0x00000004
} nexus_io_flags_t;


struct nexus_dirent {
    char                name[NAME_MAX];
    nexus_dirent_type_t type;
};

struct nexus_stat {
    size_t timestamp;
    size_t size;
};

/**
 * Creates a new file/dir
 * @param parent
 */
int
nexus_fs_touch(struct nexus_volume  * volume,
               char                 * parent_dir,
               char                 * plain_name,
               nexus_dirent_type_t    type,
               char                ** nexus_name);

int
nexus_fs_remove(struct nexus_volume  * volume,
                char                 * parent_dir,
                char                 * plain_name,
                char                ** nexus_name);

int
nexus_fs_lookup(struct nexus_volume  * volume,
                char                 * parent_dir,
                char                 * plain_name,
                char                ** nexus_name);

int
nexus_fs_filldir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 char                 * nexus_name,
                 char                ** plain_name);

int
nexus_fs_symlink(struct nexus_volume * volume,
                 char                * dirpath,
                 char                * link_name,
                 char                * target_path,
                 char               ** nexus_name);

int
nexus_fs_hardlink(struct nexus_volume * volume,
                  char                * link_dirpath,
                  char                * link_name,
                  char                * target_dirpath,
                  char                * target_name,
                  char               ** nexus_name);

int
nexus_fs_rename(struct nexus_volume * volume,
                char                * from_dirpath,
                char                * oldname,
                char                * to_dirpath,
                char                * newname,
                char               ** old_nexusname,
                char               ** new_nexusname);



int
nexus_fs_encrypt(struct nexus_volume * volume,
                 char                * path,
                 uint8_t             * in_buf,
                 uint8_t             * out_buf,
                 off_t                 offset,
                 size_t                size,
                 size_t                filesize);

int
nexus_fs_decrypt(struct nexus_volume * volume,
                 char                * path,
                 uint8_t             * in_buf,
                 uint8_t             * out_buf,
                 off_t                 offset,
                 size_t                size,
                 size_t                filesize);




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



