/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <nexus_fs.h>
#include <nexus_volume.h>
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
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_touch == NULL) {
	log_error("fs_touch NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_touch(volume, dirpath, plain_name, type, nexus_name, backend->priv_data);
}

int
nexus_fs_remove(struct nexus_volume  * volume,
                char                 * dirpath,
                char                 * plain_name,
                char                ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_remove == NULL) {
	log_error("fs_remove NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_remove(volume, dirpath, plain_name, nexus_name, backend->priv_data);
}

int
nexus_fs_lookup(struct nexus_volume  * volume,
                char                 * dirpath,
                char                 * plain_name,
                char                ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_lookup == NULL) {
	log_error("fs_lookup NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_lookup(volume, dirpath, plain_name, nexus_name, backend->priv_data);
}

int
nexus_fs_filldir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 char                 * nexus_name,
                 char                ** plain_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_filldir == NULL) {
	log_error("fs_filldir NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_filldir(volume, dirpath, nexus_name, plain_name, backend->priv_data);
}

int
nexus_fs_symlink(struct nexus_volume * volume,
                 char                * dirpath,
                 char                * link_name,
                 char                * target_path,
                 char               ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_symlink == NULL) {
	log_error("fs_symlink NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_symlink(volume,
                                     dirpath,
                                     link_name,
                                     target_path,
                                     nexus_name,
                                     backend->priv_data);
}

int
nexus_fs_hardlink(struct nexus_volume * volume,
                  char                * link_dirpath,
                  char                * link_name,
                  char                * target_dirpath,
                  char                * target_name,
                  char               ** nexus_name)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_symlink == NULL) {
	log_error("fs_symlink NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_hardlink(volume,
                                      link_dirpath,
                                      link_name,
                                      target_dirpath,
                                      target_name,
                                      nexus_name,
                                      backend->priv_data);
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
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_rename == NULL) {
	log_error("fs_rename NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_rename(volume,
                                    from_dirpath,
                                    oldname,
                                    to_dirpath,
                                    newname,
                                    old_nexusname,
                                    new_nexusname,
                                    backend->priv_data);
}



int
nexus_fs_encrypt(struct nexus_volume * volume,
                 char                * path,
                 uint8_t             * in_buf,
                 uint8_t             * out_buf,
                 off_t                 offset,
                 size_t                size,
                 size_t                filesize)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_encrypt == NULL) {
	log_error("fs_encrypt NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_encrypt(volume,
                                     path,
                                     in_buf,
                                     out_buf,
                                     offset,
                                     size,
                                     filesize,
                                     backend->priv_data);
}

int
nexus_fs_decrypt(struct nexus_volume * volume,
                 char                * path,
                 uint8_t             * in_buf,
                 uint8_t             * out_buf,
                 off_t                 offset,
                 size_t                size,
                 size_t                filesize)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_encrypt == NULL) {
	log_error("fs_encrypt NOT Implemented for %s backend\n", backend->impl->name);
	return -1;
    }

    return backend->impl->fs_decrypt(volume,
                                     path,
                                     in_buf,
                                     out_buf,
                                     offset,
                                     size,
                                     filesize,
                                     backend->priv_data);
}

