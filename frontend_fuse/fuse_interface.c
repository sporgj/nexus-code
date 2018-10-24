#include "nexus_fuse.h"

#if 0
static void
nxs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{

}
#endif

static void
__copy_statbuf(struct nexus_stat * nexus_stat, struct stat * st)
{
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

    if (nexus_fuse_stat(dentry, dentry->name, &nexus_stat)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    __copy_statbuf(&nexus_stat, &stbuf);

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

    if (nexus_fuse_stat(dentry, filename, &nexus_stat)) {
        nexus_free(filename);
        fuse_reply_err(req, ENOENT);
        return;
    }

    __copy_statbuf(&nexus_stat, &entry_param.attr);

    if (vfs_add_dentry(dentry, filename, entry_param.attr.st_ino) == NULL) {
        log_error("could not add dentry\n");

        nexus_free(filename);
        fuse_reply_err(req, ENOENT);
        return;
    }

    nexus_free(filename);

    entry_param.ino = entry_param.attr.st_ino;

    fuse_reply_entry(req, &entry_param);
}


static void
nxs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info * fi)
{
    struct my_dentry    * dentry  = vfs_get_dentry(ino);
    struct nexus_dirent * entries = NULL;

    size_t real_offset    = off; // FIXME: this only works for off=0
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

        entry_size = fuse_add_direntry(req, readdir_ptr, readdir_left, curr_dirent->name, &st, next_offset);

        if (entry_size > readdir_left) {
            // we know we have exceeded the capacity
            break;
        }

        readdir_left -= entry_size;
        readdir_ptr  += entry_size;
    }

    nexus_free(entries);


    fuse_reply_buf(req, readdir_buffer, size - readdir_left);
    nexus_free(readdir_buffer);
}


static struct fuse_lowlevel_ops nxs_fuse_ops = {
    .lookup                 = nxs_fuse_lookup,
    // .open                   = nxs_fuse_open,
    .readdir                = nxs_fuse_readdir,
    .getattr                = nxs_fuse_getattr,
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
