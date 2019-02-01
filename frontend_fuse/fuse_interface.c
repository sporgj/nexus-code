#include "nexus_fuse.h"




/* these represent expiry dates for FUSE entries and inodes */

#define FUSE_ENTRY_TIMEOUT              10

#define FUSE_ATTR_TIMEOUT               5





/**
 * called whenever FUSE needs to create an entry (e.g., lookup, create, mkdir etc)
 */
static int
__export_fuse_entry(struct my_dentry        * dentry,
                    struct my_inode         * inode,
                    struct fuse_entry_param * entry_param)
{
    struct stat * st_dest = &entry_param->attr;

    st_dest->st_mode = nexus_fs_sys_mode_from_type(dentry->type);

    switch(dentry->type) {
    case NEXUS_DIR:
        st_dest->st_nlink = 2;
        break;
    default:
        st_dest->st_nlink = 1;
        break;
    }

    // if the inode, is fresh, just grab the attributes there
    // XXX: there should probably be a timeout
    if (inode->last_accessed) {
        memcpy(st_dest, &inode->attrs.posix_stat, sizeof(struct stat));
    } else if (nexus_fuse_stat_inode(dentry, inode)) {
        return -1;
    }


    st_dest->st_ino = inode->ino;

    if (dentry->type == NEXUS_REG) {
        if (inode->is_dirty) {
            st_dest->st_size = inode->filesize;
        } else {
            st_dest->st_size = inode->attrs.posix_stat.st_size;
        }
    }

    entry_param->ino           = st_dest->st_ino;
    entry_param->entry_timeout = FUSE_ENTRY_TIMEOUT;
    entry_param->attr_timeout  = 0;

    return 0;
}



static void
nxs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dentry  * dentry = NULL;

    struct my_inode   * inode  = NULL;

    struct stat         stbuf;

    int code = ENOENT;


    if (fi && fi->fh) {
        struct my_file * file_ptr = (struct my_file *)fi->fh;

        dentry = file_ptr->dentry;

        inode = inode_get(file_ptr->inode);
    } else {
        dentry = vfs_get_dentry(ino, &inode);

        if (dentry == NULL) {
            log_error("could not find inode (%zu)\n", ino);
            goto exit;
        }
    }


    if (nexus_fuse_getattr(dentry, NEXUS_STAT_LINK, &inode->attrs)) {
        goto out_err;
    }

    memcpy(&stbuf, &inode->attrs.posix_stat, sizeof(struct stat));


    // override the file size accordingly (inode could be dirty)
    if (dentry->type == NEXUS_REG) {
        stbuf.st_size = inode->filesize;
    }

    fuse_reply_attr(req, &stbuf, FUSE_ATTR_TIMEOUT);

    code = 0;

out_err:
    inode_put(inode);
exit:
    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_setattr(fuse_req_t              req,
                 fuse_ino_t              ino,
                 struct stat           * new_stat_values,
                 int                     to_set,
                 struct fuse_file_info * fi)
{
    struct my_dentry  * dentry = NULL;

    struct my_inode   * inode  = NULL;

    struct stat         stbuf;

    struct nexus_fs_attr nexus_attrs;

    int code = ENOENT;


    (void)fi; // TODO check this for open files


    memcpy(&nexus_attrs.posix_stat, new_stat_values, sizeof(struct stat));


    dentry = vfs_get_dentry(ino, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        goto exit;
    }


    if (nexus_fuse_setattr(dentry, &nexus_attrs, to_set)) {
        goto out_err;
    }

    memcpy(&stbuf, &nexus_attrs.posix_stat, sizeof(struct stat));

    fuse_reply_attr(req, &stbuf, FUSE_ATTR_TIMEOUT);

    code = 0;

out_err:
    inode_put(inode);
exit:
    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    struct my_dentry    * parent_dentry  = NULL;

    struct my_inode     * parent_inode   = NULL;

    struct my_dentry    * child_dentry   = NULL;

    char                * filename = strndup(name, NEXUS_NAME_MAX);

    struct nexus_fs_lookup a_lookup;

    struct fuse_entry_param entry_param  = { 0 };

    int code = ENOENT;


    parent_dentry = vfs_get_dentry(parent, &parent_inode);

    if (parent_dentry == NULL) {
        log_error("could not find inode (%zu)\n", parent);
        goto exit;
    }


    child_dentry = dentry_lookup(parent_dentry, name);

    if (nexus_fuse_lookup(parent_dentry, filename, &a_lookup)) {
        if (child_dentry) {
            vfs_forget_dentry(parent_dentry, filename);
        }

        vfs_forget_dentry(parent_dentry, filename);
        goto out_err;
    }


    // cache the entry into the vfs
    if (child_dentry == NULL) {
        child_dentry = _vfs_cache_dentry(parent_dentry, filename, &a_lookup);

        if (child_dentry == NULL) {
            log_error("could not cache dentry (%s)\n", filename);
            goto out_err;
        }
    }

    nexus_free(filename);


    if (__export_fuse_entry(child_dentry, child_dentry->inode, &entry_param)) {
        log_error("__export_fuse_entry FAILED\n");
        goto out_err;
    }

    inode_incr_lookup(child_dentry->inode, 1);

    fuse_reply_entry(req, &entry_param);

    code = 0;
out_err:
    inode_put(parent_inode);
exit:
    nexus_free(filename);

    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    struct my_inode * inode = vfs_get_inode(ino);

    if (inode) {
        inode_decr_lookup(inode, nlookup);
    }

    fuse_reply_none(req);
}

static void
nxs_fuse_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data * forgets)
{
    for (size_t i = 0; i < count; i++) {
        struct my_inode * inode = vfs_get_inode(forgets[i].ino);

        if (inode) {
            inode_decr_lookup(inode, forgets[i].nlookup);
        }
    }

    fuse_reply_none(req);
}

static void
nxs_fuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dir    * dir_ptr = NULL;

    struct my_dentry * dentry  = NULL;

    struct my_inode  * inode   = NULL;

    int code = ENOENT;


    dentry = vfs_get_dentry(ino, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        goto exit;
    }

    // if this was not checked for awhile, let's update the stat info
    // XXX: makes this an expiry date
    if (!inode->last_accessed) {
        // this updates last_accessed
        if (nexus_fuse_getattr(dentry, NEXUS_STAT_FILE, &inode->attrs)) {
            code = ENOENT;
            log_error("nexus_fuse_getattr() FAILED\n");
            goto out_err;
        }
    }

    dir_ptr = vfs_dir_alloc(dentry);

    if (dir_ptr == NULL) {
        log_error("could not create dir\n");
        goto out_err;
    }


    dir_ptr->file_count = inode->attrs.stat_info.filecount;

    fi->fh = (uintptr_t)dir_ptr;

    fuse_reply_open(req, fi);

    code = 0;

out_err:
    inode_put(inode);
exit:
    if (code) {
        fuse_reply_err(req, code);
    }
}


static void
nxs_fuse_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dir * dir_ptr = (struct my_dir *)fi->fh;

    if (dir_ptr) {
        vfs_dir_free(dir_ptr);
        fi->fh = (uintptr_t)NULL;
    }

    fuse_reply_err(req, 0);
}

static void
nxs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info * fi)
{
    struct my_dir       * dir_ptr = (struct my_dir *)fi->fh;

    struct my_inode     * inode   = NULL;

    struct my_dentry    * dentry  = vfs_get_dentry(ino, &inode);
    struct nexus_dirent * entries = NULL;

    size_t real_offset    = off; // FIXME: this MIGHT only works for off=0
    size_t result_count   = 0;
    size_t directory_size = 0;

    off_t next_offset = real_offset;

    char * readdir_buffer = NULL;
    char * readdir_ptr    = NULL;
    size_t readdir_left   = size;

    int code = ENOTDIR;


    if (dentry == NULL) {
        goto exit;
    }


    if (dir_ptr->readdir_offset >= dir_ptr->file_count) {
        inode_put(inode);
        fuse_reply_err(req, 0);
        return;
    }

    entries = nexus_fuse_readdir(dentry, real_offset, &result_count, &directory_size);

    if (entries == NULL) {
        code = EINVAL;
        goto out_err;
    }


    readdir_ptr = readdir_buffer = nexus_malloc(readdir_left);

    for (size_t i = 0; i < result_count; i++) {
        struct nexus_dirent * curr_dirent = &entries[i];
        size_t entry_size;
        struct stat st;

        st.st_mode = nexus_fs_sys_mode_from_type(curr_dirent->type);

        st.st_ino = nexus_uuid_hash(&curr_dirent->uuid);

        next_offset += 1;

        entry_size = fuse_add_direntry(req,
                                       readdir_ptr,
                                       readdir_left,
                                       curr_dirent->name,
                                       &st,
                                       next_offset);

        if (entry_size > readdir_left) {
            // we know we have exceeded the capacity
            break;
        }

        readdir_left -= entry_size;
        readdir_ptr  += entry_size;

        dir_ptr->readdir_offset += 1;
    }

    nexus_free(entries);


    fuse_reply_buf(req, readdir_buffer, size - readdir_left);
    nexus_free(readdir_buffer);

    code = 0;

out_err:
    inode_put(inode);
exit:
    if (code) {
        fuse_reply_err(req, code);
    }
}

static inline struct my_dentry *
__create_file_or_dir(fuse_req_t               req,
                     fuse_ino_t               parent,
                     const char             * name,
                     mode_t                   mode,
                     nexus_dirent_type_t      type,
                     struct nexus_stat      * nexus_stat)
{
    char             * filename = strndup(name, NEXUS_NAME_MAX);

    struct my_inode  * inode    = NULL;

    struct my_dentry * dentry   = vfs_get_dentry(parent, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", parent);
        return NULL;
    }

    if (nexus_fuse_create(dentry, filename, type, mode, nexus_stat)) {
        inode_put(inode);
        log_error("nexus_fuse_touch (%s/) -> (%s) FAILED\n", dentry->name, name);
        return NULL;
    }

    inode_put(inode);

    return vfs_cache_dentry(dentry, filename, &nexus_stat->uuid, nexus_stat->type);
}

static void
nxs_fuse_create(
    fuse_req_t req, fuse_ino_t parent, const char * name, mode_t mode, struct fuse_file_info * fi)
{
    struct my_dentry * new_dentry = NULL;

    struct my_inode  * new_inode  = NULL;

    struct my_file   * file_ptr = NULL;

    struct nexus_stat nexus_stat;

    struct fuse_entry_param entry_param;


    new_dentry = __create_file_or_dir(req, parent, name, mode, NEXUS_REG, &nexus_stat);

    if (new_dentry == NULL) {
        log_error("could not create file\n");
        return;
    }


    file_ptr = vfs_file_alloc(new_dentry, fi->flags);

    if (file_ptr == NULL) {
        log_error("could not create vfs file\n");
        fuse_reply_err(req, ENOENT); // XXX EAGAIN?
        return;
    }

    if (__export_fuse_entry(new_dentry, new_dentry->inode, &entry_param)) {
        file_close(file_ptr);
        log_error("__export_fuse_entry FAILED\n");
        fuse_reply_err(req, ENOENT); // XXX EAGAIN?
        return;
    }

    inode_get(new_inode);
    inode_incr_lookup(new_dentry->inode, 1);
    inode_put(new_inode);

    fi->fh = (uintptr_t)file_ptr;

    fuse_reply_create(req, &entry_param, fi);
}

static void
nxs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char * name, mode_t mode)
{
    struct my_dentry * new_dentry = NULL;
    struct my_inode  * new_inode  = NULL;

    struct nexus_stat nexus_stat;

    struct fuse_entry_param entry_param;


    new_dentry = __create_file_or_dir(req, parent, name, mode, NEXUS_DIR, &nexus_stat);

    if (new_dentry == NULL) {
        log_error("could not create file\n");
        fuse_reply_err(req, ENOENT); // XXX EAGAIN?
        return;
    }

    if (__export_fuse_entry(new_dentry, new_dentry->inode, &entry_param)) {
        log_error("__export_fuse_entry FAILED\n");
        fuse_reply_err(req, ENOENT); // XXX EAGAIN?
        return;
    }

    new_inode = new_dentry->inode;

    inode_get(new_inode);
    inode_incr_lookup(new_inode, 1);
    inode_put(new_inode);

    fuse_reply_entry(req, &entry_param);
}

static void
nxs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_file   * file_ptr = NULL;
    struct my_inode  * inode    = NULL;
    struct my_dentry * dentry   = vfs_get_dentry(ino, &inode);

    int code = EIO;

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        fuse_reply_err(req, ENOENT);
        return;
    }


    // if this was not checked for awhile, let's update the stat info
    // XXX: makes this an expiry date
    if (!inode->last_accessed) {
        // this updates last_accessed
        if (nexus_fuse_getattr(dentry, NEXUS_STAT_FILE, &inode->attrs)) {
            code = ENOENT;
            log_error("nexus_fuse_getattr() FAILED\n");
            goto out_err;
        }
    }

    if (!inode_is_file(inode) && !(fi->flags & O_CREAT)) {
        code = EISDIR;
        log_error("tried to open directory\n");
        goto out_err;
    }


    file_ptr = vfs_file_alloc(dentry, fi->flags);

    if (file_ptr == NULL) {
        code = ENOENT;
        log_error("could not create vfs file\n");
        goto out_err;
    }


    inode_incr_lookup(dentry->inode, 1);

    fi->fh = (uintptr_t)file_ptr;

    fuse_reply_open(req, fi);

    code = 0;
out_err:
    inode_put(inode);

    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_file * file_ptr = (struct my_file *)fi->fh;

    int ret = nexus_fuse_store(file_ptr);

    if (file_ptr) {
        file_close(file_ptr);
    }

    fuse_reply_err(req, ret);
}

static void
nxs_fuse_remove(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    fuse_ino_t ino;

    struct my_inode   * inode  = NULL;

    struct my_dentry  * dentry = vfs_get_dentry(parent, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", parent);
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (nexus_fuse_remove(dentry, (char *)name, &ino)) {
        inode_put(inode);
        log_error("nexus_fuse_remove (%s/) -> (%s) FAILED\n", dentry->name, name);
        fuse_reply_err(req, EAGAIN);
        return;
    }

    vfs_forget_dentry(dentry, (char *)name);

    fuse_reply_err(req, 0);

    inode_put(inode);
}


static void
nxs_fuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
    char * target = NULL;

    struct my_inode  * inode    = NULL;

    struct my_dentry * dentry   = vfs_get_dentry(ino, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (nexus_fuse_readlink(dentry, &target)) {
        inode_put(inode);
        log_error("nexus_fuse_readlink (%s) FAILED\n", dentry->name);
        fuse_reply_err(req, EINVAL);
        return;
    }

    fuse_reply_readlink(req, target);

    nexus_free(target);

    inode_put(inode);
}


static void
nxs_fuse_symlink(fuse_req_t req, const char * link, fuse_ino_t parent, const char * name)
{
    struct my_inode  * parent_inode  = NULL;
    struct my_dentry * parent_dentry = vfs_get_dentry(parent, &parent_inode);

    struct my_dentry * new_dentry = NULL;

    struct nexus_stat stat_info;

    struct fuse_entry_param entry_param;

    int code = EIO;


    if (parent_dentry == NULL) {
        log_error("could not get inode (%zu)\n", parent);
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (nexus_fuse_symlink(parent_dentry, (char *)name, (char *)link, &stat_info)) {
        log_error("could not symlink (%s -> %s)\n", name, link);
        goto out_err;
    }

    new_dentry = vfs_cache_dentry(parent_dentry, (char *)name, &stat_info.uuid, stat_info.type);

    if (new_dentry == NULL) {
        log_error("could not add dentry to vfs\n");
        goto out_err;
    }

    if (__export_fuse_entry(new_dentry, new_dentry->inode, &entry_param)) {
        log_error("__export_fuse_entry FAILED\n");
        goto out_err;
    }

    inode_incr_lookup(new_dentry->inode, 1);

    fuse_reply_entry(req, &entry_param);

    code = 0;
out_err:
    inode_put(parent_inode);

    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_hardlink(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char * newname)
{
    struct my_inode  * linkdir_inode  = NULL;
    struct my_dentry * linkdir_dentry = NULL;
    struct my_inode  * target_inode  = NULL;
    struct my_dentry * target_dentry = NULL;

    struct my_dentry * new_dentry = NULL;

    struct fuse_entry_param entry_param = { 0 };

    int code = ENOENT;


    linkdir_dentry = vfs_get_dentry(newparent, &linkdir_inode);

    if (linkdir_dentry == NULL) {
        log_error("could not get link directory dentry\n");
        goto out_err;
    }

    target_dentry = vfs_get_dentry(ino, &target_inode);

    if (target_dentry == NULL) {
        log_error("could not get target file dentry\n");
        goto out_err;
    }

    if (nexus_fuse_hardlink(linkdir_dentry, (char *)newname, target_dentry)) {
        code = EIO;

        log_error("could not hardlink\n");
        goto out_err;
    }

    new_dentry = vfs_cache_dentry(linkdir_dentry, (char *)newname, &target_inode->uuid, NEXUS_REG);

    if (new_dentry == NULL) {
        code = EIO;
        log_error("could not add dentry to vfs\n");
        goto out_err;
    }

    if (__export_fuse_entry(new_dentry, new_dentry->inode, &entry_param)) {
        log_error("__export_fuse_entry FAILED\n");
        goto out_err;
    }

    inode_get(new_dentry->inode);
    inode_incr_lookup(new_dentry->inode, 1);
    inode_put(new_dentry->inode);

    fuse_reply_entry(req, &entry_param);

    code = 0;
out_err:
    if (linkdir_inode) {
        inode_put(linkdir_inode);
    }

    if (target_inode) {
        inode_put(target_inode);
    }

    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_rename(fuse_req_t   req,
                fuse_ino_t   parent,
                const char * name,
                fuse_ino_t   newparent,
                const char * newname,
                unsigned int flags)
{
    struct my_inode  * src_inode  = NULL;
    struct my_inode  * dst_inode  = NULL;
    struct my_dentry * src_dentry = vfs_get_dentry(parent, &src_inode);
    struct my_dentry * dst_dentry = vfs_get_dentry(newparent, &dst_inode);

    int code = ENOENT;

    (void)flags; // TODO handle rename flags (RENAME_EXCHANGE/RENAME_NOREPLACE)

    if (src_dentry == NULL || dst_dentry == NULL) {
        log_error("could not fetch source/dest dentries\n");
        goto out_err;
    }


    if (nexus_fuse_rename(src_dentry, (char *)name, dst_dentry, (char *)newname)) {
        log_error("nexus_fuse_rename FAILED\n");
        goto out_err;
    }

    vfs_forget_dentry(dst_dentry, (char *)newname);

    if (parent == newparent) {
        struct my_dentry * child = dentry_lookup(src_dentry, (char *)name);

        if (child) {
            dentry_set_name(child, (char *)newname);
        }
    } else {
        vfs_forget_dentry(src_dentry, (char *)name);
    }

    fuse_reply_err(req, 0);

    code = 0;
out_err:
    if (src_inode) {
        inode_put(src_inode);
    }

    if (dst_inode) {
        inode_put(dst_inode);
    }

    if (code) {
        fuse_reply_err(req, code);
    }
}

static void
nxs_fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info * fi)
{
    struct my_file * file_ptr = (struct my_file *)fi->fh;

    const uint8_t * first_buffer = NULL;    // we will try to fit all the data here
    const uint8_t * other_buffer = NULL;

    size_t          first_buflen = 0;
    size_t          other_buflen = 0;

    struct fuse_bufvec * bufvec  = NULL;    // this will hold buffer vectors



    pthread_rwlock_rdlock(&file_ptr->io_lock);

    first_buffer = file_read_dataptr(file_ptr, off, size, &first_buflen);

    if (first_buffer == NULL) {
        log_error("file_read_dataptr(). file=%s, size=%zu FAILED\n", file_ptr->filepath,
                  file_ptr->inode->filesize);
        pthread_rwlock_unlock(&file_ptr->io_lock);
        fuse_reply_err(req, EIO);
        return;
    }


    // we have all the data, we can return early
    if (first_buflen == size) {
        fuse_reply_buf(req, (const char *)first_buffer, first_buflen);
        goto exit;
    }


    // otherwise, we may need to read from two chunks
    {
        size_t new_offset = off + first_buflen;
        size_t new_length = size - first_buflen;

        other_buffer = file_read_dataptr(file_ptr, new_offset, new_length, &other_buflen);

        if (other_buffer == NULL) {
            log_error("file_read_dataptr() FAILED\n");
            pthread_rwlock_unlock(&file_ptr->io_lock);
            fuse_reply_err(req, EIO);
            return;
        }


        bufvec = nexus_malloc(sizeof(struct fuse_bufvec) + sizeof(struct fuse_buf));

        bufvec->count       = 2;

        bufvec->buf[0].size = first_buflen;
        bufvec->buf[0].mem  = (void *)first_buffer;

        bufvec->buf[1].size = other_buflen;
        bufvec->buf[1].mem  = (void *)other_buffer;

        fuse_reply_data(req, bufvec, FUSE_BUF_NO_SPLICE);

        nexus_free(bufvec);
    }


exit:
    file_ptr->total_sent += (first_buflen + other_buflen);

    pthread_rwlock_unlock(&file_ptr->io_lock);
}

static void
nxs_fuse_write(fuse_req_t              req,
               fuse_ino_t              ino,
               const char *            buffer,
               size_t                  size,
               off_t                   off,
               struct fuse_file_info * fi)
{
    struct my_file * file_ptr = (struct my_file *)fi->fh;

    pthread_rwlock_wrlock(&file_ptr->io_lock);

    size_t bytes_read = 0;

    if (file_write(file_ptr, off, size, (uint8_t *)buffer, &bytes_read)) {
        log_error("writing file failed\n");
        pthread_rwlock_unlock(&file_ptr->io_lock);
        fuse_reply_err(req, EIO);
        return;
    }

    file_ptr->total_recv += bytes_read;

    fuse_reply_write(req, (int)bytes_read);

    pthread_rwlock_unlock(&file_ptr->io_lock);
}

static void
nxs_fuse_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_file * file_ptr = (struct my_file *)fi->fh;

    int ret = nexus_fuse_store(file_ptr);

    fuse_reply_err(req, ret);
}

static void
nxs_fuse_init(void * userdata, struct fuse_conn_info * conn)
{
    if (conn->capable & FUSE_CAP_WRITEBACK_CACHE) {
        // nexus_printf("nexus-fuse: activating writeback\n");
        // conn->want |= FUSE_CAP_WRITEBACK_CACHE;
    }
}


static struct fuse_lowlevel_ops nxs_fuse_ops = {
    .lookup                 = nxs_fuse_lookup,
    .getattr                = nxs_fuse_getattr,
    .setattr                = nxs_fuse_setattr,
    .forget                 = nxs_fuse_forget,
    .forget_multi           = nxs_fuse_forget_multi,
    .create                 = nxs_fuse_create,
    .unlink                 = nxs_fuse_remove,
    .open                   = nxs_fuse_open,
    .release                = nxs_fuse_release,
    .opendir                = nxs_fuse_opendir,
    .releasedir             = nxs_fuse_releasedir,
    .readdir                = nxs_fuse_readdir,
    .mkdir                  = nxs_fuse_mkdir,
    .rmdir                  = nxs_fuse_remove,
    .readlink               = nxs_fuse_readlink,
    .symlink                = nxs_fuse_symlink,
    .link                   = nxs_fuse_hardlink,
    .rename                 = nxs_fuse_rename,

    .read                   = nxs_fuse_read,
    .write                  = nxs_fuse_write,
    .flush                  = nxs_fuse_flush,

    .init                   = nxs_fuse_init,
};

int
start_fuse(int argc, char * argv[], bool foreground, char * mount_path)
{
    struct fuse_args         args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *    se   = NULL;
    struct fuse_cmdline_opts opts;

    int ret = -1;

    if (fuse_parse_cmdline(&args, &opts) != 0) {
        return 1;
    }

    // github.com/libfuse/libfuse/blob/master/example/hello_ll.c
    se = fuse_session_new(&args, &nxs_fuse_ops, sizeof(nxs_fuse_ops), NULL);
    if (se == NULL) {
        goto err_out1;
    }

    if (fuse_set_signal_handlers(se) != 0) {
        goto err_out2;
    }

    if (fuse_session_mount(se, mount_path) != 0) {
        goto err_out3;
    }

    fuse_daemonize(foreground);

    /* Block until ctrl+c or fusermount -u */
    if (opts.singlethread)
        ret = fuse_session_loop(se);
    else
        ret = fuse_session_loop_mt(se, opts.clone_fd);

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    return ret ? 1 : 0;
}
