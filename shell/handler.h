/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>

#include <nexus_fs.h>


int
__fs_touch(struct nexus_volume * vol, const char * path, nexus_dirent_type_t type);

int
__fs_remove(struct nexus_volume * vol, const char * path);

int
__fs_ls(struct nexus_volume * vol, char * dirpath);

int
__fs_stat(struct nexus_volume * vol, char * path);

int
__fs_getattr(struct nexus_volume * vol, char * path);

int
__fs_symlink(struct nexus_volume * vol, char * path, char * target);

int
__fs_readlink(struct nexus_volume * vol, char * path);

int
__fs_hardlink(struct nexus_volume * vol, char * link_filepath, char * target_filepath);


int
dispatch_nexus_command(uint8_t    * cmd_buf,
                       uint32_t     cmd_size,
                       uint8_t   ** resp_buf,
                       uint32_t   * resp_size);
