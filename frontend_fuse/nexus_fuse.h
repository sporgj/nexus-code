#pragma once

#include <nexus.h>
#include <nexus_util.h>
#include <nexus_volume.h>


#include "vfs.h"


extern struct nexus_volume      * nexus_fuse_volume;

/**
 * Starts the FUSE filesystem, at specified mount point
 */
int
start_fuse(int argc, char * argv[], bool foreground, char * mount_path);




// handlers

struct nexus_dirent *
nexus_fuse_readdir(struct my_dentry * dentry, size_t offset, size_t * result_count, size_t * directory_size);


int
nexus_fuse_lookup(struct my_dentry * dentry, char * filename, struct nexus_fs_lookup * lookup_info);

int
nexus_fuse_stat(struct my_dentry * dentry, struct nexus_stat * stat);

int
nexus_fuse_getattr(struct my_dentry * dentry, struct nexus_fs_attr * attrs);

int
nexus_fuse_setattr(struct my_dentry * dentry, struct nexus_fs_attr * attrs, int to_set);


int
nexus_fuse_touch(struct my_dentry  * dentry,
                 char              * filename,
                 nexus_dirent_type_t type,
                 struct nexus_stat * nexus_stat);

int
nexus_fuse_remove(struct my_dentry * dentry, char * filename, fuse_ino_t * ino);

int
nexus_fuse_readlink(struct my_dentry * dentry, char ** target);


int
nexus_fuse_symlink(struct my_dentry  * dentry,
                   char              * name,
                   char              * target,
                   struct nexus_stat * nexus_stat);


int
nexus_fuse_fetch_chunk(struct my_file * file_ptr, struct file_chunk * file_chunk);

int
nexus_fuse_store(struct my_file * file_ptr);
