#include "nexus_fuse.h"

#include <nexus_file_handle.h>

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
nexus_fuse_stat(struct my_dentry * dentry, nexus_stat_flags_t stat_flags, struct nexus_stat * stat_info)
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
__derive_stat_info(struct stat * posix_stat, struct nexus_stat * stat_info, mode_t file_type)
{
    // make sure st.st_size contains the info returned from the backend
    // posix_stat->st_size = stat_info->size;

    switch (stat_info->type) {
    case NEXUS_REG:
        posix_stat->st_nlink = stat_info->link_count;
        posix_stat->st_size = stat_info->filesize;
        break;
    case NEXUS_DIR:
        posix_stat->st_nlink = 2;
        break;
    case NEXUS_LNK:
        posix_stat->st_nlink = 1;
        break;
    }

    posix_stat->st_mode = (stat_info->mode | file_type);

    posix_stat->st_ino = nexus_uuid_hash(&stat_info->uuid);

    // FIXME: what about st_blocks (amount of disk space in units of 512-byte blocks
}

int
nexus_fuse_getattr(struct my_dentry     * dentry,
                   nexus_stat_flags_t     stat_flags,
                   struct nexus_fs_attr * attrs)
{
    struct nexus_stat * stat_info = &attrs->stat_info;

    struct nexus_uuid * uuid = NULL;

    char * path = dentry_get_fullpath(dentry);

    int ret = -1;


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

    // stat the datastores
    switch (dentry->type) {
    case NEXUS_DIR:
        ret = nexus_datastore_getattr(nexus_fuse_volume->metadata_store, uuid, attrs);
        break;
    case NEXUS_REG:
        ret = nexus_datastore_getattr(nexus_fuse_volume->data_store, uuid, attrs);
        break;
    case NEXUS_LNK:
        // we will just return stat information about its parent
        ret = nexus_datastore_getattr(nexus_fuse_volume->metadata_store,
                                      &dentry->parent->inode->attrs.stat_info.uuid,
                                      attrs);
    }

    if (ret) {
        goto out;
    }

    __derive_stat_info(&attrs->posix_stat, stat_info, nexus_fs_sys_mode_from_type(dentry->type));
out:
    nexus_free(path);

    return ret;
}


int
nexus_fuse_setattr(struct my_dentry * dentry, struct nexus_fs_attr * attrs, int to_set)
{
    struct nexus_stat * stat_info = &attrs->stat_info;

    nexus_fs_attr_flags_t flags = to_set; // the to_set flags and nexus flags are the same

    char * path = dentry_get_fullpath(dentry);

    int ret = -1;


    if (path == NULL) {
        return -1;
    }

    if (nexus_fs_setattr(nexus_fuse_volume, path, attrs, flags)) {
        log_error("could not stat backend (filepath=%s)\n", path);
        nexus_free(path);
        return -1;
    }

    // XXX: need to revise this at a future time
    // there's no need to split this away from the backend (nexus_fs_setattr). but I want to try this for now
    if (dentry->type == NEXUS_REG) {
        ret = nexus_datastore_setattr(
            nexus_fuse_volume->data_store, &stat_info->uuid, attrs, flags);
    } else if (dentry->type == NEXUS_DIR) {
        ret = nexus_datastore_setattr(
            nexus_fuse_volume->metadata_store, &stat_info->uuid, attrs, flags);
    }

    if (ret) {
        log_error("nexus_datastore_setattr FAILED\n");
        nexus_free(path);
        return -1;
    }

    __derive_stat_info(&attrs->posix_stat, stat_info, nexus_fs_sys_mode_from_type(dentry->type));

    nexus_free(path);

    return 0;
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
                        (nexus_file_mode_t)mode,
                        &nexus_stat->uuid)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    if (type == NEXUS_REG) {
        if (nexus_datastore_new_uuid(nexus_fuse_volume->data_store, &nexus_stat->uuid, NULL)) {
            nexus_free(parent_dirpath);
            log_error("could not create datastore file\n");
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
    struct nexus_uuid uuid;
    char * parent_dirpath = dentry_get_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_remove(nexus_fuse_volume, parent_dirpath, filename, &uuid)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    *ino = nexus_uuid_hash(&uuid);

    nexus_free(parent_dirpath);

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
    char * to_dirpath = dentry_get_fullpath(to_dentry);

    int ret = -1;


    if (from_dirpath && to_dirpath) {
        struct nexus_uuid entry_uuid;
        struct nexus_uuid overwrite_uuid;

        ret = nexus_fs_rename(nexus_fuse_volume,
                              from_dirpath,
                              oldname,
                              to_dirpath,
                              newname,
                              &entry_uuid,
                              &overwrite_uuid);
    }

    nexus_free(from_dirpath);
    nexus_free(to_dirpath);

    return ret;
}

int
nexus_fuse_fetch_chunk(struct my_file * file_ptr, struct file_chunk * chunk)
{
    struct nexus_datastore   * datastore   = nexus_fuse_volume->data_store;

    struct nexus_file_handle * file_handle = NULL;

    uint8_t encrypted_buffer[NEXUS_CHUNK_SIZE] = { 0 };


    file_handle = nexus_datastore_fopen(datastore, &file_ptr->inode->uuid, NULL, NEXUS_FREAD);

    if (file_handle == NULL) {
        log_error("could not get the file handle from datastore\n");
        return -1;
    }

    if (chunk->base) {
        lseek(file_handle->fd, chunk->base, SEEK_SET);
    }

    size_t nbytes = read(file_handle->fd, encrypted_buffer, chunk->size);

    if (nbytes != chunk->size) {
        log_error("fetching chunk %zu file='%s' (tried=%zu, got=%zu)\n",
                  chunk->index, file_handle->filepath, chunk->size, nbytes);
        goto out_err;
    }

    if (nexus_fs_decrypt(nexus_fuse_volume,
                         file_ptr->filepath,
                         encrypted_buffer,
                         chunk->buffer,
                         chunk->base,
                         chunk->size,
                         file_ptr->filesize)) {
        log_error("nexus_fs_decrypt() failed (offset=%zu, file=%s)\n", chunk->base, file_ptr->filepath);
        goto out_err;
    }

    nexus_datastore_fclose(datastore, file_handle);

    return 0;

out_err:
    nexus_datastore_fclose(datastore, file_handle);

    return -1;
}

int
nexus_fuse_store(struct my_file * file_ptr)
{
    struct nexus_datastore   * datastore   = nexus_fuse_volume->data_store;

    struct nexus_file_handle * file_handle = NULL;

    struct list_head         * chunk_iter  = NULL;

    uint8_t encrypted_buffer[NEXUS_CHUNK_SIZE] = { 0 };


    if (!file_ptr->is_dirty) {
        return 0;
    }

    file_handle = nexus_datastore_fopen(
        datastore, &file_ptr->inode->uuid, NULL, NEXUS_FRDWR);

    if (file_handle == NULL) {
        log_error("could not get file handle from datastore\n");
        return -1;
    }


    if (ftruncate(file_handle->fd, file_ptr->filesize)) {
        log_error("ftruncate FAILED (datafile=%s, size=%zu)\n",
                  file_handle->filepath,
                  file_ptr->filesize);
        goto out_err;
    }

    list_for_each(chunk_iter, &file_ptr->file_chunks) {
        struct file_chunk * chunk = list_entry(chunk_iter, struct file_chunk, node);

        if (nexus_fs_encrypt(nexus_fuse_volume,
                             file_ptr->filepath,
                             chunk->buffer,
                             encrypted_buffer,
                             chunk->base,
                             chunk->size,
                             file_ptr->filesize)) {
            log_error("could not encrypt the buffer\n");
            goto out_err;
        }

        lseek(file_handle->fd, chunk->base, SEEK_SET);

        size_t nbytes = write(file_handle->fd, encrypted_buffer, chunk->size);

        if (nbytes != chunk->size) {
            log_error("writing chunk %zu (tried=%zu, got=%zu)\n", chunk->index, chunk->size, nbytes);
            goto out_err;
        }
    }


    // printf("file written (%s) filepath=%s, filesize=%zu\n",
    //         file_handle->filepath, file_ptr->filepath, file_ptr->filesize);

    nexus_datastore_fclose(datastore, file_handle);

    file_set_clean(file_ptr);

    return 0;

out_err:
    nexus_datastore_fclose(datastore, file_handle);
    return -1;
}
