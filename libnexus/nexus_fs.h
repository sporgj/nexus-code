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

#include "nexus_uuid.h"

struct nexus_volume;

#define NEXUS_NAME_MAX  256
#define NEXUS_PATH_MAX  1024

typedef enum {
    NEXUS_REG = 1,  /* regular file */
    NEXUS_DIR = 2,  /* directory    */
    NEXUS_LNK = 3   /* symlink      */
} nexus_dirent_type_t;


typedef enum {
    NEXUS_FREAD          = 0x00000001,
    NEXUS_FWRITE         = 0x00000002,
    NEXUS_FRDWR          = NEXUS_FREAD | NEXUS_FWRITE,

    NEXUS_FCREATE        = 0x00000004,
    NEXUS_FDELETE        = 0x00000008
} nexus_io_flags_t;


struct nexus_dirent {
    char                name[NEXUS_NAME_MAX];
    struct nexus_uuid   uuid;
    nexus_dirent_type_t type;
};

struct nexus_stat {
    size_t              timestamp;
    size_t              size;

    struct nexus_uuid   uuid;

    nexus_dirent_type_t type;
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
                struct nexus_uuid    * uuid);
int
nexus_fs_stat(struct nexus_volume  * volume,
              char                 * dirpath,
              char                 * plain_name,
              struct nexus_stat    * nexus_stat);

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
nexus_fs_readdir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 struct nexus_dirent  * dirent_buffer_array,
                 size_t                 dirent_buffer_count,
                 size_t                 offset,
                 size_t               * result_count,
                 size_t               * directory_size);




int
nexus_fs_delete(struct nexus_volume * volume,
		char                * path);


int
nexus_fs_create(struct nexus_volume * volume,
		char                * path,
		nexus_dirent_type_t   type,
		struct nexus_stat   * stat);



