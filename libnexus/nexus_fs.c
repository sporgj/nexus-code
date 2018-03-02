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
nexus_fs_readdir(struct nexus_volume * volume, char * path, struct nexus_dirent ** result)
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



int
nexus_fs_touch(struct nexus_volume  * volume,
               char                 * dirpath,
               char                 * plain_name,
               nexus_dirent_type_t    type,
               char                ** nexus_name)
{
    return nexus_backend_fs_touch(volume, dirpath, plain_name, type, nexus_name);
}

int
nexus_fs_remove(struct nexus_volume  * volume,
                char                 * dirpath,
                char                 * plain_name,
                char                ** nexus_name)
{
    return nexus_backend_fs_remove(volume, dirpath, plain_name, nexus_name);
}

int
nexus_fs_lookup(struct nexus_volume  * volume,
                char                 * dirpath,
                char                 * plain_name,
                char                ** nexus_name)
{
    return nexus_backend_fs_lookup(volume, dirpath, plain_name, nexus_name);
}

int
nexus_fs_filldir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 char                 * nexus_name,
                 char                ** plain_name)
{
    return nexus_backend_fs_filldir(volume, dirpath, nexus_name, plain_name);
}

int
nexus_fs_symlink(struct nexus_volume * volume,
                 char                * dirpath,
                 char                * link_name,
                 char                * target_path,
                 char               ** nexus_name)
{
    return nexus_backend_fs_symlink(volume, dirpath, link_name, target_path, nexus_name);
}

int
nexus_fs_hardlink(struct nexus_volume * volume,
                  char                * link_dirpath,
                  char                * link_name,
                  char                * target_dirpath,
                  char                * target_name,
                  char               ** nexus_name)
{
    return nexus_backend_fs_hardlink(volume,
                                     link_dirpath,
                                     link_name,
                                     target_dirpath,
                                     target_name,
                                     nexus_name);
}

int
nexus_fs_rename(struct nexus_volume * volume,
                char                * from_dirpath,
                char                * oldname,
                char                * to_dirpath,
                char                * newname,
                char               ** old_nexusname,
                char               ** new_nexusname)
{
    return nexus_backend_fs_rename(volume,
                                   from_dirpath,
                                   oldname,
                                   to_dirpath,
                                   newname,
                                   old_nexusname,
                                   new_nexusname);
}
