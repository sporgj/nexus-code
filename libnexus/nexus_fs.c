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
nexus_fs_create(struct nexus_volume  * volume,
                char                 * dirpath,
                char                 * name,
                nexus_dirent_type_t    type,
                struct nexus_uuid    * uuid)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_create == NULL) {
        log_error("fs_touch NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_create(volume, dirpath, name, type, uuid, backend->priv_data);
}

int
nexus_fs_remove(struct nexus_volume     * volume,
                char                    * dirpath,
                char                    * plain_name,
                struct nexus_fs_lookup  * lookup_info,
                bool                    * should_remove)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_remove == NULL) {
        log_error("fs_remove NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_remove(volume, dirpath, plain_name, lookup_info, should_remove, backend->priv_data);
}

int
nexus_fs_lookup(struct nexus_volume    * volume,
                char                   * parent_dir,
                char                   * plain_name,
                struct nexus_fs_lookup * lookup_info)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_lookup == NULL) {
        log_error("fs_lookup NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_lookup(volume, parent_dir, plain_name, lookup_info, backend->priv_data);
}

int
nexus_fs_stat(struct nexus_volume  * volume,
              char                 * path,
              nexus_stat_flags_t     stat_flags,
              struct nexus_stat    * nexus_stat)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_stat == NULL) {
        log_error("fs_stat NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_stat(volume, path, stat_flags, nexus_stat, backend->priv_data);
}

int
nexus_fs_readdir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 struct nexus_dirent  * dirent_buffer_array,
                 size_t                 dirent_buffer_count,
                 size_t                 offset,
                 size_t               * result_count,
                 size_t               * directory_size)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_readdir == NULL) {
        log_error("fs_readdir NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_readdir(volume,
                                     dirpath,
                                     dirent_buffer_array,
                                     dirent_buffer_count,
                                     offset,
                                     result_count,
                                     directory_size,
                                     backend->priv_data);
}

int
nexus_fs_symlink(struct nexus_volume * volume,
                 char                * dirpath,
                 char                * link_name,
                 char                * target_path,
                 struct nexus_stat   * stat_info)
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
                                     &stat_info->uuid,
                                     backend->priv_data);
}

int
nexus_fs_readlink(struct nexus_volume * volume, char * dirpath, char * linkname, char ** target_path)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_readlink == NULL) {
        log_error("fs_readlink NOT implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_readlink(volume, dirpath, linkname, target_path, backend->priv_data);
}

int
nexus_fs_hardlink(struct nexus_volume * volume,
                  char                * link_dirpath,
                  char                * link_name,
                  char                * target_dirpath,
                  char                * target_name,
                  struct nexus_uuid   * uuid)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_hardlink == NULL) {
        log_error("fs_hardlink NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_hardlink(volume,
                                      link_dirpath,
                                      link_name,
                                      target_dirpath,
                                      target_name,
                                      uuid,
                                      backend->priv_data);
}

int
nexus_fs_rename(struct nexus_volume     * volume,
                char                    * from_dirpath,
                char                    * oldname,
                char                    * to_dirpath,
                char                    * newname,
                struct nexus_uuid       * entry_uuid,
                struct nexus_fs_lookup  * overriden_entry,
                bool                    * should_remove)
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
                                    entry_uuid,
                                    overriden_entry,
                                    should_remove,
                                    backend->priv_data);
}


int
nexus_fs_truncate(struct nexus_volume * volume,
                  char                * filepath,
                  size_t                size,
                  struct nexus_stat   * stat)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_truncate == NULL) {
        log_error("fs_truncate NOT Implemented for %s backend\n", backend->impl->name);
        return -1;
    }

    return backend->impl->fs_truncate(volume, filepath, size, stat, backend->priv_data);
}


struct nexus_file_crypto *
nexus_fs_file_encrypt_start(struct nexus_volume * volume, char * filepath, size_t filesize)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_file_encrypt_start == NULL) {
        log_error("fs_file_encrypt_start is NOT implemented\n");
        return NULL;
    }

    return backend->impl->fs_file_encrypt_start(volume, filepath, filesize, backend->priv_data);
}

struct nexus_file_crypto *
nexus_fs_file_decrypt_start(struct nexus_volume * volume, char * filepath)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_file_decrypt_start == NULL) {
        log_error("fs_file_decrypt_start is NOT implemented\n");
        return NULL;
    }

    return backend->impl->fs_file_decrypt_start(volume, filepath, backend->priv_data);
}

int
nexus_fs_file_crypto_seek(struct nexus_volume      * volume,
                          struct nexus_file_crypto * file_crypto,
                          size_t                     offset)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_file_crypto_seek == NULL) {
        log_error("fs_file_crypto_seek is NOT implemented\n");
        return -1;
    }

    return backend->impl->fs_file_crypto_seek(file_crypto, offset);
}

int
nexus_fs_file_crypto_encrypt(struct nexus_volume      * volume,
                             struct nexus_file_crypto * file_crypto,
                             const uint8_t            * plaintext_input,
                             uint8_t                  * encrypted_output,
                             size_t                     size,
                             size_t                   * processed_bytes)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_file_crypto_encrypt == NULL) {
        log_error("fs_file_crypto_encrypt is NOT implemented\n");
        return -1;
    }

    return backend->impl->fs_file_crypto_encrypt(file_crypto,
                                                 plaintext_input,
                                                 encrypted_output,
                                                 size,
                                                 processed_bytes);
}

int
nexus_fs_file_crypto_decrypt(struct nexus_volume      * volume,
                             struct nexus_file_crypto * file_crypto,
                             uint8_t                  * decrypted_output,
                             size_t                     size,
                             size_t                   * processed_bytes)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_file_crypto_decrypt == NULL) {
        log_error("fs_file_crypto_decrypt is NOT implemented\n");
        return -1;
    }

    return backend->impl->fs_file_crypto_decrypt(file_crypto,
                                                 decrypted_output,
                                                 size,
                                                 processed_bytes);
}

int
nexus_fs_file_crypto_finish(struct nexus_volume * volume, struct nexus_file_crypto * file_crypto)
{
    struct nexus_backend * backend = volume->backend;

    if (backend->impl->fs_file_crypto_finish == NULL) {
        log_error("fs_file_crypto_finish is NOT implemented\n");
        return -1;
    }

    return backend->impl->fs_file_crypto_finish(file_crypto);
}
