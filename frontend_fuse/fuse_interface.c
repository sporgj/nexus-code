#include "nexus_fuse.h"


static void
__sys_stat_from_nexus_stat(struct stat * st, struct nexus_stat * nexus_stat)
{
    memset(st, 0, sizeof(struct stat));

    if (nexus_stat->type == NEXUS_DIR) {
        st->st_mode = S_IFDIR;
        st->st_nlink = 2;
    } else if (nexus_stat->type == NEXUS_LNK) {
        st->st_mode = S_IFLNK;
        st->st_nlink = 1;
    } else {
        st->st_mode = S_IFREG;
        st->st_nlink = 1;
        st->st_size = nexus_stat->size;
    }

    st->st_ino = nexus_uuid_hash(&nexus_stat->uuid);
}

static inline void
__set_entry_param_stat(struct fuse_entry_param * entry_param, struct nexus_stat * nexus_stat)
{
    __sys_stat_from_nexus_stat(&entry_param->attr, nexus_stat);
    entry_param->ino = entry_param->attr.st_ino;
}


static void
nxs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dentry  * dentry = NULL;

    struct stat         stbuf;

    struct nexus_stat   nexus_stat;



    if (ino == FUSE_ROOT_ID) {
        stbuf.st_mode = S_IFDIR;
        stbuf.st_nlink = 2;

        fuse_reply_attr(req, &stbuf, 1.0);
        return;
    }


    dentry = vfs_get_dentry(ino);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        fuse_reply_err(req, ENOENT);
        return;
    }


    memset(&stbuf, 0, sizeof(struct stat));

    // XXX: find ways to avoid this call (check dentry cache)
    // since the dentry is already cached
    if (nexus_fuse_stat(dentry, &nexus_stat)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    __sys_stat_from_nexus_stat(&stbuf, &nexus_stat);

    fuse_reply_attr(req, &stbuf, 1.0);
}

/**
 * Because our READDIR implementation returns inode numbers, it seems FUSE skips this
 * function and goes straight to GETATTR.
 */
static void
nxs_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    struct my_dentry    * dentry  = vfs_get_dentry(parent);

    char                * filename = strndup(name, NEXUS_NAME_MAX);

    struct nexus_stat   nexus_stat;

    struct fuse_entry_param entry_param;


    memset(&entry_param, 0, sizeof(struct fuse_entry_param));

    if (nexus_fuse_lookup(dentry, filename, &nexus_stat)) {
        goto out_err;
    }

    if (vfs_add_dentry(dentry, filename, &nexus_stat.uuid, nexus_stat.type) == NULL) {
        log_error("could not add dentry\n");
        goto out_err;
    }

    nexus_free(filename);


    __set_entry_param_stat(&entry_param, &nexus_stat);

    fuse_reply_entry(req, &entry_param);
    return;

out_err:
    nexus_free(filename);
    fuse_reply_err(req, ENOENT);
}


static void
nxs_fuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dir    * dir_ptr = NULL;
    struct my_dentry * dentry  = NULL;

    struct nexus_stat   nexus_stat;


    dentry = vfs_get_dentry(ino);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", ino);
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (nexus_fuse_stat(dentry, &nexus_stat)) {
        fuse_reply_err(req, ENOENT);
        return;
    }


    dir_ptr = nexus_malloc(sizeof(struct my_dir));

    dir_ptr->dentry     = dentry;
    dir_ptr->file_count = nexus_stat.size;

    fi->fh = (uintptr_t)dir_ptr;

    fuse_reply_open(req, fi);
}


static void
nxs_fuse_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct my_dir * dir_ptr = (struct my_dir *)fi->fh;

    if (dir_ptr) {
        nexus_free(dir_ptr);
        fi->fh = (uintptr_t)NULL;
    }

    fuse_reply_err(req, 0);
}

static void
nxs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info * fi)
{
    struct my_dir       * dir_ptr = (struct my_dir *)fi->fh;

    struct my_dentry    * dentry  = vfs_get_dentry(ino);
    struct nexus_dirent * entries = NULL;

    size_t real_offset    = off; // FIXME: this MIGHT only works for off=0
    size_t result_count   = 0;
    size_t directory_size = 0;

    off_t next_offset = real_offset;

    char * readdir_buffer = NULL;
    char * readdir_ptr    = NULL;
    size_t readdir_left   = size;

    (void) fi;


    if (dentry == NULL) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }


    if (dir_ptr->readdir_offset >= dir_ptr->file_count) {
        fuse_reply_err(req, 0);
        return;
    }

    entries = nexus_fuse_readdir(dentry, real_offset, &result_count, &directory_size);

    if (entries == NULL) {
        fuse_reply_err(req, EAGAIN);
        return;
    }


    readdir_ptr = readdir_buffer = nexus_malloc(readdir_left);

    for (size_t i = 0; i < result_count; i++) {
        struct nexus_dirent * curr_dirent = &entries[i];
        size_t entry_size;
        struct stat st;

        if (curr_dirent->type == NEXUS_REG) {
            st.st_mode = S_IFREG;
        } else if (curr_dirent->type == NEXUS_DIR) {
            st.st_mode = S_IFDIR;
        } else {
            st.st_mode = S_IFLNK;
        }


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
}

static inline int
__create_file_or_dir(fuse_req_t               req,
                     fuse_ino_t               parent,
                     const char             * name,
                     mode_t                   mode,
                     nexus_dirent_type_t      type,
                     struct nexus_stat      * nexus_stat,
                     struct fuse_file_info  * fi)
{
    char             * filename = strndup(name, NEXUS_NAME_MAX);

    struct my_dentry * dentry   = vfs_get_dentry(parent);


    (void)mode; // XXX: we probably have to handle this for POSIX compat.


    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", parent);
        fuse_reply_err(req, ENOENT);
        goto out_err;
    }

    if (nexus_fuse_touch(dentry, filename, type, nexus_stat)) {
        log_error("nexus_fuse_touch (%s/) -> (%s) FAILED\n", dentry->name, name);
        fuse_reply_err(req, EAGAIN);
        goto out_err;
    }


    if (vfs_add_dentry(dentry, filename, &nexus_stat->uuid, nexus_stat->type) == NULL) {
        log_error("could not add dentry\n");
        nexus_free(filename);
    }

    return 0;

out_err:
    return -1;
}

static void
nxs_fuse_create(
    fuse_req_t req, fuse_ino_t parent, const char * name, mode_t mode, struct fuse_file_info * fi)
{
    struct nexus_stat nexus_stat;

    struct fuse_entry_param entry_param;

    printf("O_CREAT2: %d\n", fi->flags & O_CREAT);

    if (__create_file_or_dir(req, parent, name, mode, NEXUS_REG, &nexus_stat, fi)) {
        return;
    }

    __set_entry_param_stat(&entry_param, &nexus_stat);

    fuse_reply_create(req, &entry_param, fi);
}

static void
nxs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char * name, mode_t mode)
{
    struct nexus_stat nexus_stat;

    struct fuse_entry_param entry_param;

    if (__create_file_or_dir(req, parent, name, mode, NEXUS_DIR, &nexus_stat, NULL)) {
        return;
    }

    fuse_reply_entry(req, &entry_param);
}

#if 0
static void
nxs_fuse_open(fuse_req_t req, fuse_ino_t parent, struct fuse_file_info * fi)
{
    // TODO
}
#endif



static void
nxs_fuse_remove(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    fuse_ino_t ino;

    struct my_dentry  * dentry = vfs_get_dentry(parent);

    if (dentry == NULL) {
        log_error("could not find inode (%zu)\n", parent);
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (nexus_fuse_remove(dentry, (char *)name, &ino)) {
        log_error("nexus_fuse_remove (%s/) -> (%s) FAILED\n", dentry->name, name);
        fuse_reply_err(req, EAGAIN);
        return;
    }

    vfs_remove_inode(ino);

    fuse_reply_err(req, 0);
}



static struct fuse_lowlevel_ops nxs_fuse_ops = {
    .lookup                 = nxs_fuse_lookup,
    .getattr                = nxs_fuse_getattr,
    .create                 = nxs_fuse_create,
    .unlink                 = nxs_fuse_remove,
    // .open                   = nxs_fuse_open,
    .opendir                = nxs_fuse_opendir,
    .releasedir             = nxs_fuse_releasedir,
    .readdir                = nxs_fuse_readdir,
    .mkdir                  = nxs_fuse_mkdir,
    .rmdir                  = nxs_fuse_remove,
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
