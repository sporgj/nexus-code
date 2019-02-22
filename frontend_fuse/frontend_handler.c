#include "nexus_fuse.h"

#include <nexus_file_handle.h>


static uint8_t __file_crypto_buffer__[NEXUS_CHUNK_SIZE] __attribute__ ((__aligned__(4096)));

static pthread_mutex_t  __file_crypto_buffer_mutex__;


struct nexus_dirent *
nexus_fuse_readdir(struct my_dentry * dentry,
                   size_t             offset,
                   size_t           * result_count,
                   size_t           * directory_size)
{
    size_t dirent_count = 128;

    struct nexus_dirent * result = nexus_malloc(dirent_count * sizeof(struct nexus_dirent));


    char * dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return NULL;
    }

    if (nexus_fs_readdir(nexus_fuse_volume,
                         dirpath,
                         result,
                         dirent_count,
                         offset,
                         result_count,
                         directory_size)) {
        nexus_free(dirpath);
        nexus_free(result);
        return NULL;
    }

    nexus_free(dirpath);

    return result;
}

int
nexus_fuse_stat(struct my_dentry *  dentry,
                nexus_stat_flags_t  stat_flags,
                struct nexus_stat * stat_info)
{
    char * dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return -1;
    }


    memset(stat_info, 0, sizeof(struct nexus_stat));

    if (nexus_fs_stat(nexus_fuse_volume, dirpath, stat_flags, stat_info)) {
        nexus_free(dirpath);
        return -1;
    }

    nexus_free(dirpath);

    return 0;
}

static void
__derive_stat_info(struct stat *         posix_stat,
                   struct nexus_stat *   stat_info,
                   struct my_dentry * dentry)
{
    switch (stat_info->type) {
    case NEXUS_REG:
        posix_stat->st_nlink = stat_info->link_count;
        posix_stat->st_size = stat_info->filesize;
        break;
    case NEXUS_DIR:
        posix_stat->st_nlink = 2;
        posix_stat->st_size = 0;
        break;
    case NEXUS_LNK:
        posix_stat->st_size = 0;
        posix_stat->st_nlink = 1;
        break;
    }

    // remove the previous bit for type, and set it to directory
    posix_stat->st_mode &= ~(S_IFREG | S_IFDIR);
    posix_stat->st_mode |= nexus_fs_sys_mode_from_type(dentry->type);

    posix_stat->st_uid = current_user_id;
    posix_stat->st_gid = current_user_id;

    posix_stat->st_ino = dentry->inode->ino;
}

static int
__datastore_getattr(struct my_dentry *     dentry,
                    struct nexus_uuid *    uuid,
                    struct nexus_fs_attr * attrs)
{
    int ret = -1;

    // stat the datastores
    switch (dentry->type) {
    case NEXUS_DIR:
    case NEXUS_REG:
        ret = nexus_datastore_getattr(nexus_fuse_volume->metadata_store, uuid, attrs);
        break;
    case NEXUS_LNK:
        // we will just return stat information about its parent
        ret = nexus_datastore_getattr(nexus_fuse_volume->metadata_store,
                                      &dentry->parent->inode->attrs.stat_info.uuid,
                                      attrs);
    }

    return ret;
}

int
nexus_fuse_stat_inode(struct my_dentry * dentry, struct my_inode * inode)
{
    struct nexus_fs_attr attrs;

    struct stat * inode_posix_stat = &inode->attrs.posix_stat;

    if (__datastore_getattr(dentry, &inode->uuid, &attrs)) {
        log_error("__datastore_getattr() FAILED\n");
        return -1;
    }

    inode_posix_stat->st_mode  = (attrs.posix_stat.st_mode & ~(S_IFREG | S_IFDIR));
    inode_posix_stat->st_mode |= nexus_fs_sys_mode_from_type(dentry->type);

    inode_posix_stat->st_uid = current_user_id;
    inode_posix_stat->st_gid = current_user_id;

    inode_posix_stat->st_ino = inode->ino;

    inode_posix_stat->st_atime = attrs.posix_stat.st_atime;
    inode_posix_stat->st_mtime = attrs.posix_stat.st_mtime;
    inode_posix_stat->st_ctime = attrs.posix_stat.st_ctime;

    return 0;
}

int
nexus_fuse_getattr(struct my_dentry     * dentry,
                   nexus_stat_flags_t     stat_flags,
                   struct nexus_fs_attr * attrs)
{
    struct nexus_stat * stat_info = &attrs->stat_info;

    struct my_inode   * inode = dentry->inode;

    struct nexus_uuid * uuid = NULL;

    char              * path = NULL;

    int ret = -1;


    if (inode && inode->last_accessed) {
        struct nexus_fs_attr attrs = { 0 };

        uuid = &inode->attrs.stat_info.uuid;

        if (inode->is_dirty) {
            // then we shall use the live chunks
            return 0;
        }

        if (__datastore_getattr(dentry, uuid, &attrs)) {
            return -1;
        }

        // if the access time is not later...
        if (attrs.posix_stat.st_mtime <= inode->attrs.posix_stat.st_mtime) {
            return 0;
        }

        inode->last_accessed = attrs.posix_stat.st_atime;
    }


    path = dentry_get_fullpath(dentry);

    if (path == NULL) {
        return -1;
    }

    memset(stat_info, 0, sizeof(struct nexus_stat));


    if (nexus_fs_stat(nexus_fuse_volume, path, stat_flags, stat_info)) {
        log_error("could not stat backend (filepath=%s)\n", path);
        goto out;
    }


    if (dentry->parent == NULL || stat_flags & NEXUS_STAT_FILE) {
        uuid = &stat_info->uuid;
    } else {
        uuid =  &stat_info->link_uuid;
    }

    // XXX: maybe we don't need to stat this if the uuid's didn't change?
    if (__datastore_getattr(dentry, uuid, attrs)) {
        goto out;
    }

    __derive_stat_info(&attrs->posix_stat, stat_info, dentry);

    if (inode->last_accessed == 0 && !inode->is_dirty) {
        inode->filesize = attrs->posix_stat.st_size;
    }

    inode->last_accessed = attrs->posix_stat.st_atime;
    inode->on_disk_size  = attrs->posix_stat.st_size;

    ret = 0;
out:
    nexus_free(path);

    return ret;
}


int
nexus_fuse_setattr(struct my_dentry * dentry, struct nexus_fs_attr * attrs, int flags)
{
    struct nexus_uuid * uuid = &dentry->inode->uuid;

    struct nexus_stat * stat_info = &dentry->inode->attrs.stat_info;

    struct stat * old_stat = &dentry->inode->attrs.posix_stat;
    struct stat * new_stat = &attrs->posix_stat;

    char * path = dentry_get_fullpath(dentry);


    if (path == NULL) {
        return -1;
    }

    if (flags & FUSE_SET_ATTR_SIZE) {
        if (nexus_fs_truncate(nexus_fuse_volume, path, new_stat->st_size, stat_info)) {
            log_error("could not stat backend (filepath=%s)\n", path);
            nexus_free(path);
            return -1;
        }
    } else if (flags & FUSE_SET_ATTR_MODE) {
        if (nexus_datastore_set_mode(nexus_fuse_volume->metadata_store, uuid, new_stat->st_mode)) {
            log_error("nexus_datastore_set_mode() FAILED\n");
            goto out_err;
        }

        old_stat->st_atime = new_stat->st_atime;
    } else if ((flags & FUSE_SET_ATTR_ATIME) || (flags & FUSE_SET_ATTR_MTIME)) {
        size_t atime = (flags & FUSE_SET_ATTR_ATIME) ? new_stat->st_atime : 0;
        size_t mtime = (flags & FUSE_SET_ATTR_MTIME) ? new_stat->st_mtime : 0;

        if (nexus_datastore_set_times(nexus_fuse_volume->metadata_store, uuid, atime, mtime)) {
            log_error("nexus_datastore_set_times() FAILED\n");
            goto out_err;
        }

        if (flags & FUSE_SET_ATTR_ATIME) {
            old_stat->st_atime = new_stat->st_atime;
        }

        if (flags & FUSE_SET_ATTR_MTIME) {
            old_stat->st_mtime = new_stat->st_mtime;
        }
    }

    __derive_stat_info(new_stat, stat_info, dentry);

    nexus_free(path);

    return 0;

out_err:
    nexus_free(path);
    return -1;
}

int
nexus_fuse_lookup(struct my_dentry * dentry, char * filename, struct nexus_fs_lookup * lookup_info)
{
    char * dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_lookup(nexus_fuse_volume, dirpath, filename, lookup_info)) {
        nexus_free(dirpath);
        return -1;
    }

    nexus_free(dirpath);

    return 0;
}

int
nexus_fuse_create(struct my_dentry  * dentry,
                  char              * filename,
                  nexus_dirent_type_t type,
                  mode_t              mode,
                  struct nexus_stat * nexus_stat)
{
    char * parent_dirpath = dentry_get_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    memset(nexus_stat, 0, sizeof(struct nexus_stat));

    // XXX: we probably need an EEXIST
    if (nexus_fs_create(nexus_fuse_volume,
                        parent_dirpath,
                        filename,
                        type,
                        &nexus_stat->uuid)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    if (type == NEXUS_REG && (mode & NEXUS_POSIX_EXEC_MODE)) {
        if (nexus_datastore_set_mode(nexus_fuse_volume->metadata_store, &nexus_stat->uuid, mode)) {
            log_error("nexus_datastore_set_mode() FAILED\n");
            nexus_free(parent_dirpath);
            return -1;
        }
    }

    // setup the stat info
    nexus_stat->type = type;

    nexus_free(parent_dirpath);

    return 0;
}

int
nexus_fuse_remove(struct my_dentry * dentry, char * filename, fuse_ino_t * ino)
{
    struct nexus_fs_lookup lookup_info;
    char * dirpath = dentry_get_fullpath(dentry);

    bool should_remove = true;

    if (dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_remove(nexus_fuse_volume, dirpath, filename, &lookup_info, &should_remove)) {
        nexus_free(dirpath);
        return -1;
    }

    *ino = nexus_uuid_hash(&lookup_info.uuid);

    nexus_free(dirpath);

    return 0;
}

int
nexus_fuse_readlink(struct my_dentry * dentry, char ** target)
{
    char * parent_dirpath = dentry_get_parent_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    int ret = nexus_fs_readlink(nexus_fuse_volume, parent_dirpath, dentry->name, target);

    nexus_free(parent_dirpath);

    return ret;
}

int
nexus_fuse_symlink(struct my_dentry  * dentry,
                   char              * name,
                   char              * target,
                   struct nexus_stat * stat_info)
{
    char * parent_dirpath = dentry_get_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_symlink(nexus_fuse_volume, parent_dirpath, name, target, stat_info)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    stat_info->type = NEXUS_LNK;

    nexus_free(parent_dirpath);

    return 0;
}

int
nexus_fuse_hardlink(struct my_dentry * linkdir_dentry, char * linkname, struct my_dentry * target)
{
    char * link_dirpath = dentry_get_fullpath(linkdir_dentry);
    char * target_dirpath = dentry_get_parent_fullpath(target);

    int ret = -1;


    if (link_dirpath && target_dirpath) {
        struct nexus_uuid hardlink_uuid;

        ret = nexus_fs_hardlink(nexus_fuse_volume,
                                link_dirpath,
                                linkname,
                                target_dirpath,
                                target->name,
                                &hardlink_uuid);
    }

    if (link_dirpath) {
        nexus_free(link_dirpath);
    }

    if (target_dirpath) {
        nexus_free(target_dirpath);
    }

    return ret;
}

int
nexus_fuse_rename(struct my_dentry * from_dentry,
                  char             * oldname,
                  struct my_dentry * to_dentry,
                  char             * newname)
{
    char * from_dirpath = dentry_get_fullpath(from_dentry);
    char * to_dirpath   = dentry_get_fullpath(to_dentry);

    int ret = -1;


    if (from_dirpath && to_dirpath) {
        struct nexus_uuid entry_uuid;
        struct nexus_fs_lookup overwrite_entry;

        bool should_remove = false;

        ret = nexus_fs_rename(nexus_fuse_volume,
                              from_dirpath,
                              oldname,
                              to_dirpath,
                              newname,
                              &entry_uuid,
                              &overwrite_entry,
                              &should_remove);
    }

    if (from_dirpath) {
        nexus_free(from_dirpath);
    }

    if (to_dirpath) {
        nexus_free(to_dirpath);
    }

    return ret;
}

int
nexus_fuse_fetch_chunk(struct my_file * file_ptr, struct file_chunk * chunk)
{
    struct my_inode          * inode       = file_ptr->inode;

    struct nexus_file_crypto * file_crypto = NULL;

    size_t size   = 0;
    size_t processed = 0;


    file_crypto = nexus_fs_file_decrypt_start(nexus_fuse_volume, file_ptr->filepath);

    if (file_crypto == NULL) {
        log_error("nexus_fs_file_encrypt_start() FAILED\n");
        goto out_err;
    }


    size = min(NEXUS_CHUNK_SIZE, inode->filesize - chunk->base);

    chunk->size = size;

    if (nexus_fs_file_crypto_seek(nexus_fuse_volume, file_crypto, chunk->base)) {
        log_error("nexus_fs_file_crypto_seek() FAILED\n");
        goto out_err;
    }

    if (nexus_fs_file_crypto_decrypt(nexus_fuse_volume,
                                     file_crypto,
                                     chunk->buffer,
                                     size,
                                     &processed)) {
        log_error("nexus_fs_file_crypto_decrypt() FAILED. chunk %zu (size=%zu, processed=%zu)\n",
                chunk->index,
                size,
                processed);
        goto out_err;
    }

    chunk->size = processed;

    if (nexus_fs_file_crypto_finish(nexus_fuse_volume, file_crypto)) {
        file_crypto = NULL;
        log_error("nexus_fs_file_crypto_finish() FAILED\n");
        goto out_err;
    }

    return 0;

out_err:
    if (file_crypto) {
        nexus_fs_file_crypto_finish(nexus_fuse_volume, file_crypto);
    }

    return -1;
}

int
nexus_fuse_store(struct my_file * file_ptr)
{
    struct my_inode          * inode       = file_ptr->inode;

    struct nexus_file_crypto * file_crypto = NULL;

    struct list_head         * chunk_iter  = NULL;


    pthread_mutex_lock(&inode->lock);

    if (!inode->is_dirty || inode->is_deleted) {
        file_set_clean(file_ptr);
        inode_set_clean(inode);
        pthread_mutex_unlock(&inode->lock);
        return 0;
    }


    if (inode->openers > 1) {
        file_set_clean(file_ptr);
        pthread_mutex_unlock(&inode->lock);
        return 0;
    }

    file_crypto = nexus_fs_file_encrypt_start(nexus_fuse_volume, file_ptr->filepath, inode->filesize);

    if (file_crypto == NULL) {
        log_error("nexus_fs_file_encrypt_start() FAILED\n");
        goto out_err;
    }


    list_for_each(chunk_iter, &inode->file_chunks) {
        struct file_chunk * chunk = list_entry(chunk_iter, struct file_chunk, node);

        size_t size = min(NEXUS_CHUNK_SIZE, inode->filesize - chunk->base);
        size_t processed = 0;

        if (nexus_fs_file_crypto_seek(nexus_fuse_volume, file_crypto, chunk->base)) {
            log_error("nexus_fs_file_crypto_seek() FAILED\n");
            goto out_err;
        }

        pthread_mutex_lock(&__file_crypto_buffer_mutex__);

        // TODO handle processed correctly
        if (nexus_fs_file_crypto_encrypt(nexus_fuse_volume,
                                         file_crypto,
                                         chunk->buffer,
                                         __file_crypto_buffer__,
                                         size,
                                         &processed)) {
            log_error("nexus_fs_file_crypto_encrypt() FAILED. chunk %zu (size=%zu, processed=%zu)\n",
                      chunk->index,
                      size,
                      processed);
            goto out_err;
        }

        pthread_mutex_unlock(&__file_crypto_buffer_mutex__);
    }


    if (nexus_fs_file_crypto_finish(nexus_fuse_volume, file_crypto)) {
        file_crypto = NULL;
        log_error("nexus_fs_file_crypto_finish() FAILED\n");
        goto out_err;
    }

    inode->on_disk_size  = inode->filesize;

    inode_set_clean(inode);

    pthread_mutex_unlock(&inode->lock);

    file_set_clean(file_ptr);

    return 0;

out_err:
    if (file_crypto) {
        nexus_fs_file_crypto_finish(nexus_fuse_volume, file_crypto);
    }

    pthread_mutex_unlock(&inode->lock);

    return -1;
}
