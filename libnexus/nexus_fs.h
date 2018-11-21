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

#include <sys/stat.h>

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


typedef uint32_t   nexus_file_mode_t; // POSIX mode is 4 bytes

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
    size_t              link_count;  // number of hardlinks

    union {
        size_t          filesize;
        size_t          filecount;
    };

    nexus_file_mode_t   mode;

    struct nexus_uuid   uuid;

    nexus_dirent_type_t type;
};


// this is derived from fuse_lowlevel.h
// https://github.com/libfuse/libfuse/blob/master/include/fuse_lowlevel.h
typedef enum {
    NEXUS_FS_ATTR_MODE      = (1 << 0),
    NEXUS_FS_ATTR_UID       = (1 << 1),
    NEXUS_FS_ATTR_GID       = (1 << 2),
    NEXUS_FS_ATTR_SIZE      = (1 << 3),
    NEXUS_FS_ATTR_ATIME     = (1 << 4),
    NEXUS_FS_ATTR_MTIME     = (1 << 5),
    NEXUS_FS_ATTR_ATIME_NOW = (1 << 7),
    NEXUS_FS_ATTR_MTIME_NOW = (1 << 8),
    NEXUS_FS_ATTR_CTIME     = (1 << 10)
} nexus_fs_attr_flags_t;


struct nexus_fs_lookup {
    struct nexus_uuid   uuid;

    nexus_dirent_type_t type;
};

// this structure will hold stat data
struct nexus_fs_attr {
    struct nexus_stat  stat_info;

    struct stat        posix_stat;
};


static inline mode_t
nexus_fs_sys_mode_from_type(nexus_dirent_type_t type)
{
    if (type == NEXUS_REG) {
        return S_IFREG;
    } else if (type == NEXUS_DIR) {
        return S_IFDIR;
    }

    return S_IFLNK;
}


/**
 * Creates a new file/dir
 * @param parent
 */
int
nexus_fs_create(struct nexus_volume  * volume,
                char                 * parent_dir,
                char                 * plain_name,
                nexus_dirent_type_t    type,
                nexus_file_mode_t      mode,
                struct nexus_uuid    * uuid);

int
nexus_fs_remove(struct nexus_volume  * volume,
                char                 * parent_dir,
                char                 * plain_name,
                struct nexus_uuid    * uuid);

int
nexus_fs_lookup(struct nexus_volume    * volume,
                char                   * parent_dir,
                char                   * plain_name,
                struct nexus_fs_lookup * lookup_info);

int
nexus_fs_setattr(struct nexus_volume   * volume,
                 char                  * path,
                 struct nexus_fs_attr  * attrs,
                 nexus_fs_attr_flags_t   flags);


int
nexus_fs_stat(struct nexus_volume  * volume,
              char                 * path,
              struct nexus_stat    * nexus_stat);

int
nexus_fs_filldir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 char                 * nexus_name,
                 char                ** plain_name);

int
nexus_fs_readdir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 struct nexus_dirent  * dirent_buffer_array,
                 size_t                 dirent_buffer_count,
                 size_t                 offset,
                 size_t               * result_count,
                 size_t               * directory_size);

int
nexus_fs_symlink(struct nexus_volume * volume,
                 char                * dirpath,
                 char                * link_name,
                 char                * target_path,
                 struct nexus_stat   * stat_info);

int
nexus_fs_readlink(struct nexus_volume * volume,
                  char                * dirpath,
                  char                * linkname,
                  char               ** target_path);

int
nexus_fs_hardlink(struct nexus_volume * volume,
                  char                * link_dirpath,
                  char                * link_name,
                  char                * target_dirpath,
                  char                * target_name,
                  struct nexus_uuid   * uuid);

int
nexus_fs_rename(struct nexus_volume * volume,
                char                * from_dirpath,
                char                * oldname,
                char                * to_dirpath,
                char                * newname,
                struct nexus_uuid   * entry_uuid,
                struct nexus_uuid   * overriden_uuid);



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
