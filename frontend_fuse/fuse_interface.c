#include "nexus_fuse.h"

#define FUSE_ENTRY_TIMEOUT   60

#define FUSE_ATTR_TIMEOUT   30


static void
nxs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dentry  * dentry = NULL;

    struct my_inode   * inode  = NULL;

    struct stat         stbuf;

    int code = ENOENT;


    dentry = vfs_get_dentry(ino, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        goto exit;
    }


    if (nexus_fuse_getattr(dentry, NEXUS_STAT_LINK, &inode->attrs)) {
        goto out_err;
    }

    memcpy(&stbuf, &inode->attrs.posix_stat, sizeof(struct stat));

    if (dentry->inode->is_dirty) {
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


    dentry_export_attrs(child_dentry, &entry_param.attr);

    entry_param.ino = entry_param.attr.st_ino;
    entry_param.entry_timeout = FUSE_ENTRY_TIMEOUT;
    entry_param.attr_timeout = 0;

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

    struct nexus_stat  nexus_stat;

    int code = ENOENT;


    dentry = vfs_get_dentry(ino, &inode);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        goto exit;
    }

    if (nexus_fuse_stat(dentry, NEXUS_STAT_FILE, &nexus_stat)) {
        goto out_err;
    }


    dir_ptr = vfs_dir_alloc(dentry);

    if (dir_ptr == NULL) {
        log_error("could not create dir\n");
        goto out_err;
    }


    dir_ptr->file_count = nexus_stat.filecount;

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

    dentry_export_attrs(new_dentry, &entry_param.attr);
    entry_param.ino = entry_param.attr.st_ino;
    entry_param.entry_timeout = FUSE_ENTRY_TIMEOUT;
    entry_param.attr_timeout = 0;

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

    dentry_export_attrs(new_dentry, &entry_param.attr);
    entry_param.ino = entry_param.attr.st_ino;
    entry_param.entry_timeout = FUSE_ENTRY_TIMEOUT;
    entry_param.attr_timeout = 0;

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

    // get the file attributes and cache them to the inode
    if (nexus_fuse_getattr(dentry, NEXUS_STAT_FILE, &inode->attrs)) {
        goto out_err;
    }

    if (!inode_is_file(dentry->inode)) {
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


    if (!inode->is_dirty) {
        inode->filesize = inode->attrs.posix_stat.st_size;
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

    dentry_export_attrs(new_dentry, &entry_param.attr);
    entry_param.ino = entry_param.attr.st_ino;
    entry_param.entry_timeout = FUSE_ENTRY_TIMEOUT;
    entry_param.attr_timeout = 0;

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

    dentry_export_attrs(new_dentry, &entry_param.attr);
    entry_param.ino = entry_param.attr.st_ino;
    entry_param.entry_timeout = FUSE_ENTRY_TIMEOUT;
    entry_param.attr_timeout = 0;

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

    uint8_t * buffer = nexus_malloc(size);
    size_t    buflen = 0;

    if (file_read(file_ptr, off, size, buffer, &buflen)) {
        fuse_reply_err(req, EIO);
        return;
    }

    fuse_reply_buf(req, (const char *)buffer, buflen);

    file_ptr->total_sent += buflen;

    free(buffer);
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

    size_t bytes_read = 0;

    if (file_write(file_ptr, off, size, (uint8_t *)buffer, &bytes_read)) {
        fuse_reply_err(req, EIO);
        return;
    }

    file_ptr->total_recv += size;

    fuse_reply_write(req, (int)bytes_read);
}

static void
nxs_fuse_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_file * file_ptr = (struct my_file *)fi->fh;

    int ret = nexus_fuse_store(file_ptr);

    fuse_reply_err(req, ret);
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
