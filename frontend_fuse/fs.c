#include "internal.h"

#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <fuse.h>
#include <assert.h>
#include <fuse_lowlevel.h>
#include <stddef.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <sys/syscall.h>

FILE *logfile;
#define TESTING_XATTR 0
#define USE_SPLICE 0

#define TRACE_FILE "/trace_stackfs.log"
#define TRACE_FILE_LEN 18
pthread_spinlock_t spinlock; /* Protecting the above spin lock */
char banner[4096];

#include "namei.c"

#if 0
static char *
__get_fullpath(const char * path)
{
    char * fullpath = NULL;

    int ret = -1;

    ret = asprintf(&fullpath, "%s/%s", datastore_path, path);

    if (ret <= 0) {
        log_error("error encoding path (%s)\n", path);
        abort();
    }

    return fullpath;
}
#endif

static void
StackFS_trace(const char * format, ...)
{
    // TODO
}

static void
stackfs_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    struct fuse_entry_param e;
    int                     res;
    char *                  fullPath = NULL;
    double                  attr_val;

    // StackFS_trace("Lookup called on name : %s, parent ino : %llu",
    //							name, parent);
    fullPath = (char *)malloc(PATH_MAX);
    construct_full_path(req, parent, fullPath, name);

    attr_val = lo_attr_valid_time(req);
    memset(&e, 0, sizeof(e));

    e.attr_timeout  = attr_val;
    e.entry_timeout = 1.0; /* dentry timeout */

    res = stat(fullPath, &e.attr);

    if (res == 0) {
        struct lo_inode * inode;

        inode = find_lo_inode(req, &e.attr, fullPath);

        if (fullPath) {
            free(fullPath);
	}

        if (!inode)
            fuse_reply_err(req, ENOMEM);
        else {
            /* store this address for faster path conversations */
            e.ino = inode->lo_ino;
            fuse_reply_entry(req, &e);
        }
    } else {
        if (fullPath)
            free(fullPath);
        fuse_reply_err(req, ENOENT);
    }
}

static void
stackfs_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    int         res;
    struct stat buf;
    (void)fi;
    double attr_val;

    // StackFS_trace("Getattr called on name : %s and inode : %llu",
    //			lo_name(req, ino), lo_inode(req, ino)->ino);
    attr_val = lo_attr_valid_time(req);
    res = stat(lo_name(req, ino), &buf);
    if (res == -1)
        return (void)fuse_reply_err(req, errno);

    fuse_reply_attr(req, &buf, attr_val);
}

static void
stackfs_ll_setattr(
    fuse_req_t req, fuse_ino_t ino, struct stat * attr, int to_set, struct fuse_file_info * fi)
{
    int res;
    (void)fi;
    struct stat buf;
    double      attr_val;

    // StackFS_trace("Setattr called on name : %s and inode : %llu",
    //			lo_name(req, ino), lo_inode(req, ino)->ino);
    attr_val = lo_attr_valid_time(req);
    if (to_set & FUSE_SET_ATTR_SIZE) {
        /*Truncate*/
        res = truncate(lo_name(req, ino), attr->st_size);
        if (res != 0) {
            return (void)fuse_reply_err(req, errno);
        }
    }

    if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
        /* Update Time */
        struct utimbuf tv;

        tv.actime  = attr->st_atime;
        tv.modtime = attr->st_mtime;

        res = utime(lo_name(req, ino), &tv);

        if (res != 0) {
            return (void)fuse_reply_err(req, errno);
        }
    }

    memset(&buf, 0, sizeof(buf));
    res = stat(lo_name(req, ino), &buf);
    if (res != 0)
        return (void)fuse_reply_err(req, errno);

    fuse_reply_attr(req, &buf, attr_val);
}

static void
stackfs_ll_create(fuse_req_t req, fuse_ino_t parent, const char * name, mode_t mode, struct fuse_file_info * fi)
{
    struct fuse_entry_param e;

    char * fullPath = NULL;

    double attr_val;

    int fd, res;

    // StackFS_trace("Create called on %s and parent ino : %llu",
    //				name, lo_inode(req, parent)->ino);

    fullPath = (char *)malloc(PATH_MAX);

    construct_full_path(req, parent, fullPath, name);

    attr_val = lo_attr_valid_time(req);

    fd = creat(fullPath, mode);

    if (fd == -1) {
        if (fullPath)
            free(fullPath);
        return (void)fuse_reply_err(req, errno);
    }

    memset(&e, 0, sizeof(e));

    e.attr_timeout  = attr_val;
    e.entry_timeout = 1.0;

    res = stat(fullPath, &e.attr);

    if (res == 0) {
        /* insert lo_inode into the hash table */
        struct lo_data *  lo_data;
        struct lo_inode * lo_inode;

        lo_inode = calloc(1, sizeof(struct lo_inode));
        if (!lo_inode) {
            if (fullPath)
                free(fullPath);

            return (void)fuse_reply_err(req, errno);
        }

        lo_inode->ino  = e.attr.st_ino;
        lo_inode->dev  = e.attr.st_dev;
        lo_inode->name = strdup(fullPath);
        /* store this for mapping (debugging) */
        lo_inode->lo_ino = (uintptr_t)lo_inode;
        lo_inode->next = lo_inode->prev = NULL;
        free(fullPath);

        lo_data = get_lo_data(req);
        pthread_spin_lock(&lo_data->spinlock);

        res = insert_to_hash_table(lo_data, lo_inode);

        pthread_spin_unlock(&lo_data->spinlock);

        if (res == -1) {
            free(lo_inode->name);
            free(lo_inode);
            fuse_reply_err(req, EBUSY);
        } else {
            lo_inode->nlookup++;
            e.ino = lo_inode->lo_ino;
            // StackFS_trace("Create called, e.ino : %llu", e.ino);
            fi->fh = fd;
            fuse_reply_create(req, &e, fi);
        }
    } else {
        if (fullPath)
            free(fullPath);
        fuse_reply_err(req, errno);
    }
}

static void
stackfs_ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char * name, mode_t mode)
{
    int                     res;
    struct fuse_entry_param e;
    char *                  fullPath = NULL;
    double                  attr_val;

    // StackFS_trace("Mkdir called with name : %s, parent ino : %llu",
    //				name, lo_inode(req, parent)->ino);

    fullPath = (char *)malloc(PATH_MAX);
    construct_full_path(req, parent, fullPath, name);
    attr_val = lo_attr_valid_time(req);

    res = mkdir(fullPath, mode);

    if (res == -1) {
        /* Error occurred while creating the directory */
        if (fullPath)
            free(fullPath);

        return (void)fuse_reply_err(req, errno);
    }

    /* Assign the stats of the newly created directory */
    memset(&e, 0, sizeof(e));
    e.attr_timeout  = attr_val;
    e.entry_timeout = 1.0; /* may be attr_val */
    res             = stat(fullPath, &e.attr);

    if (res == 0) {
        /* insert lo_inode into the hash table */
        struct lo_data *  lo_data;
        struct lo_inode * lo_inode;

        lo_inode = calloc(1, sizeof(struct lo_inode));
        if (!lo_inode) {
            if (fullPath)
                free(fullPath);

            return (void)fuse_reply_err(req, errno);
        }

        lo_inode->ino  = e.attr.st_ino;
        lo_inode->dev  = e.attr.st_dev;
        lo_inode->name = strdup(fullPath);
        /* store this for mapping (debugging) */
        lo_inode->lo_ino = (uintptr_t)lo_inode;
        lo_inode->next = lo_inode->prev = NULL;
        free(fullPath);

        lo_data = get_lo_data(req);

        pthread_spin_lock(&lo_data->spinlock);

        res = insert_to_hash_table(lo_data, lo_inode);

        pthread_spin_unlock(&lo_data->spinlock);

        if (res == -1) {
            free(lo_inode->name);
            free(lo_inode);
            fuse_reply_err(req, EBUSY);
        } else {
            lo_inode->nlookup++;
            e.ino = lo_inode->lo_ino;
            fuse_reply_entry(req, &e);
        }
    } else {
        if (fullPath)
            free(fullPath);
        fuse_reply_err(req, errno);
    }
}

static void
stackfs_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    int fd;

    fd = open(lo_name(req, ino), fi->flags);

    // StackFS_trace("Open called on name : %s and fuse inode : %llu kernel inode : %llu fd : %d",
    //		lo_name(req, ino), get_higher_fuse_inode_no(req, ino), get_lower_fuse_inode_no(req, ino),
    //fd);
    // StackFS_trace("Open name : %s and inode : %llu", lo_name(req, ino),
    // get_lower_fuse_inode_no(req, ino));

    if (fd == -1)
        return (void)fuse_reply_err(req, errno);

    fi->fh = fd;

    fuse_reply_open(req, fi);
}

static void
stackfs_ll_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    DIR *              dp;
    struct lo_dirptr * d;

    // StackFS_trace("Opendir called on name : %s and inode : %llu",
    //			lo_name(req, ino), lo_inode(req, ino)->ino);

    dp = opendir(lo_name(req, ino));

    if (dp == NULL)
        return (void)fuse_reply_err(req, errno);

    d         = malloc(sizeof(struct lo_dirptr));
    d->dp     = dp;
    d->offset = 0;
    d->entry  = NULL;

    fi->fh = (uintptr_t)d;

    fuse_reply_open(req, fi);
}

static void
stackfs_ll_read(
    fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info * fi)
{
    int res;
    (void)ino;
    // struct timespec start, end;
    // long time;
    // long time_sec;

    // StackFS_trace("StackFS Read start on inode : %llu", get_lower_fuse_inode_no(req, ino));
    if (USE_SPLICE) {
        struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

        // StackFS_trace("Splice Read name : %s, off : %lu, size : %zu",
        //			lo_name(req, ino), offset, size);

        buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
        buf.buf[0].fd    = fi->fh;
        buf.buf[0].pos   = offset;

        fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
    } else {
        char * buf;

        buf = (char *)malloc(size);

        res = pread(fi->fh, buf, size, offset);
        if (res == -1)
            return (void)fuse_reply_err(req, errno);
        res = fuse_reply_buf(req, buf, res);
        free(buf);
    }
    StackFS_trace("StackFS Read end on inode : %llu", get_lower_fuse_inode_no(req, ino));
}

static void
stackfs_ll_readdir(
    fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info * fi)
{
    struct lo_dirptr * d;
    char *             buf = NULL;
    char *             p   = NULL;
    size_t             rem;
    int                err;
    (void)ino;

    // StackFS_trace("Readdir called on name : %s and inode : %llu",
    //			lo_name(req, ino), lo_inode(req, ino)->ino);
    d   = lo_dirptr(fi);
    buf = malloc(size * sizeof(char));
    if (!buf)
        return (void)fuse_reply_err(req, ENOMEM);

    /* If offset is not same, need to seek it */
    if (off != d->offset) {
        seekdir(d->dp, off);
        d->entry  = NULL;
        d->offset = off;
    }
    p   = buf;
    rem = size;
    while (1) {
        size_t entsize;
        off_t  nextoff;

        if (!d->entry) {
            errno    = 0;
            d->entry = readdir(d->dp);
            if (!d->entry) {
                if (errno && rem == size) {
                    err = errno;
                    goto error;
                }
                break;
            }
        }
        nextoff = telldir(d->dp);

        struct stat st = {
            .st_ino = d->entry->d_ino, .st_mode = d->entry->d_type << 12,
        };
        entsize = fuse_add_direntry(req, p, rem, d->entry->d_name, &st, nextoff);
        /* The above function returns the size of the entry size even though
        * the copy failed due to smaller buf size, so I'm checking after this
        * function and breaking out incase we exceed the size.
        */
        if (entsize > rem)
            break;

        p += entsize;
        rem -= entsize;

        d->entry  = NULL;
        d->offset = nextoff;
    }

    fuse_reply_buf(req, buf, size - rem);
    free(buf);

    return;

error:
    free(buf);

    fuse_reply_err(req, err);
}

static void
stackfs_ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    (void)ino;

    // StackFS_trace("Release called on name : %s and inode : %llu fd : %d ",
    //		lo_name(req, ino), lo_inode(req, ino)->ino, fi->fh);

    close(fi->fh);

    fuse_reply_err(req, 0);
}

static void
stackfs_ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    struct lo_dirptr * d;
    (void)ino;

    // StackFS_trace("Releasedir called on name : %s and inode : %llu",
    //			lo_name(req, ino), lo_inode(req, ino)->ino);
    d = lo_dirptr(fi);

    closedir(d->dp);

    free(d);
    fuse_reply_err(req, 0);
}

static void
stackfs_ll_write(fuse_req_t              req,
                 fuse_ino_t              ino,
                 const char *            buf,
                 size_t                  size,
                 off_t                   off,
                 struct fuse_file_info * fi)
{
    int res;
    (void)ino;

    // StackFS_trace("Write name : %s, inode : %llu, off : %lu, size : %zu",
    //		lo_name(req, ino), lo_inode(req, ino)->ino, off, size);

    res = pwrite(fi->fh, buf, size, off);

    if (res == -1)
        return (void)fuse_reply_err(req, errno);

    fuse_reply_write(req, res);
}

#if USE_SPLICE
static void
stackfs_ll_write_buf(
    fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec * buf, off_t off, struct fuse_file_info * fi)
{
    int res;
    (void)ino;

    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

    // StackFS_trace("Splice Write_buf on name : %s, off : %lu, size : %zu",
    //			lo_name(req, ino), off, buf->buf[0].size);

    dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    dst.buf[0].fd    = fi->fh;
    dst.buf[0].pos   = off;
    res              = fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);

    if (res >= 0)
        fuse_reply_write(req, res);
    else
        fuse_reply_err(req, res);
}
#endif

static void
stackfs_ll_unlink(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    int    res;
    char * fullPath = NULL;

    // StackFS_trace("Unlink called on name : %s, parent inode : %llu",
    //				name, lo_inode(req, parent)->ino);
    fullPath = (char *)malloc(PATH_MAX);
    construct_full_path(req, parent, fullPath, name);

    res = unlink(fullPath);

    if (res == -1)
        fuse_reply_err(req, errno);
    else
        fuse_reply_err(req, res);

    if (fullPath)
        free(fullPath);
}

static void
stackfs_ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char * name)
{
    int    res;
    char * fullPath = NULL;

    // StackFS_trace("rmdir called with name : %s, parent inode : %llu",
    //				name, lo_inode(req, parent)->ino);
    fullPath = (char *)malloc(PATH_MAX);
    construct_full_path(req, parent, fullPath, name);
    res = rmdir(fullPath);

    if (res == -1)
        fuse_reply_err(req, errno);
    else
        fuse_reply_err(req, res);

    if (fullPath)
        free(fullPath);
}

static void
forget_inode(fuse_req_t req, struct lo_inode * inode, uint64_t nlookup)
{
    int res;

    assert(inode->nlookup >= nlookup);
    inode->nlookup -= nlookup;

    if (!inode->nlookup)
        res = delete_from_hash_table(get_lo_data(req), inode);

    (void)res;
}

static void
stackfs_ll_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    struct lo_inode * inode = lo_inode(req, ino);

    // StackFS_trace("Forget name : %s, inode : %llu and lookup count : %llu",
    //				inode->name, inode->ino, nlookup);
    forget_inode(req, inode, nlookup);

    fuse_reply_none(req);
}

static void
stackfs_ll_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data * forgets)
{
    size_t            i;
    struct lo_inode * inode;
    fuse_ino_t        ino;
    uint64_t          nlookup;

    // StackFS_trace("Batch Forget count : %zu", count);
    for (i = 0; i < count; i++) {
        ino     = forgets[i].ino;
        nlookup = forgets[i].nlookup;
        inode   = lo_inode(req, ino);

        // StackFS_trace("Forget %zu name : %s, lookup count : %llu",
        //				i, inode->name, nlookup);
        forget_inode(req, inode, nlookup);
    }

    fuse_reply_none(req);
}

static void
stackfs_ll_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info * fi)
{
    int err;

    // StackFS_trace("Flush called on name : %s and inode : %llu",
    //			lo_name(req, ino), lo_inode(req, ino)->ino);
    err = 0;
    fuse_reply_err(req, err);
}

static void
stackfs_ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
    int            res;
    struct statvfs buf;

    if (ino) {
        // StackFS_trace("Statfs called with name : %s, and inode : %llu",
        //		lo_name(req, ino), lo_inode(req, ino)->ino);
        memset(&buf, 0, sizeof(buf));
        res = statvfs(lo_name(req, ino), &buf);
    }

    if (!res)
        fuse_reply_statfs(req, &buf);
    else
        fuse_reply_err(req, res);
}

static void
stackfs_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info * fi)
{
    int res;

    // StackFS_trace("Fsync on name : %s, inode : %llu, datasync : %d",
    //	 lo_name(req, ino), lo_inode(req, ino)->ino, datasync);
    if (datasync)
        res = fdatasync(fi->fh);
    else
        res = fsync(fi->fh);

    fuse_reply_err(req, res);
}

#if TESTING_XATTR
static void
stackfs_ll_getxattr(fuse_req_t req, fuse_ino_t ino, const char * name, size_t size)
{
    int res;

    // StackFS_trace("Function Trace : Getxattr");
    if (size) {
        char * value = (char *)malloc(size);

        res = lgetxattr(lo_name(req, ino), name, value, size);
        if (res > 0)
            fuse_reply_buf(req, value, res);
        else
            fuse_reply_err(req, errno);

        free(value);
    } else {
        res = lgetxattr(lo_name(req, ino), name, NULL, 0);
        if (res >= 0)
            fuse_reply_xattr(req, res);
        else
            fuse_reply_err(req, errno);
    }
}
#endif

static struct fuse_lowlevel_ops ll_oper = {
    .lookup  = stackfs_ll_lookup,
    .getattr = stackfs_ll_getattr,
    .statfs  = stackfs_ll_statfs,
    .setattr = stackfs_ll_setattr,
    .flush   = stackfs_ll_flush,
    .fsync   = stackfs_ll_fsync,
#if TESTING_XATTR
    .getxattr = stackfs_ll_getxattr,
#endif
     .forget       = stackfs_ll_forget,
     .forget_multi = stackfs_ll_forget_multi,
     .create       = stackfs_ll_create,
     .open         = stackfs_ll_open,
     .read         = stackfs_ll_read,
     .write        = stackfs_ll_write,
#if USE_SPLICE
     .write_buf = stackfs_ll_write_buf,
#endif
     .release    = stackfs_ll_release,
     .unlink     = stackfs_ll_unlink,
     .mkdir      = stackfs_ll_mkdir,
     .rmdir      = stackfs_ll_rmdir,
     .opendir    = stackfs_ll_opendir,
     .readdir    = stackfs_ll_readdir,
     .releasedir = stackfs_ll_releasedir
};

int
start_fuse(int argc, char * argv[], char * rootDir)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    char * resolved_rootdir_path = NULL;

    struct lo_data lo;

    struct fuse_cmdline_opts opts;

    int ret = 0;


    if (fuse_parse_cmdline(&args, &opts) != 0) {
        log_error("fuse_parse_cmdline FAILED\n");
        return -1;
    }

    // TODO: sets the filesystem to run as a foreground process. Set this as DEBUG option
    // fuse_opt_add_arg(&args, "-f");


    resolved_rootdir_path = realpath(rootDir, NULL);

    if (!resolved_rootdir_path) {
        printf("There is a problem in resolving the root ");
        printf("Directory Passed %s\n", rootDir);
        perror("Error");
        return -1;
    }

    // initialize the root hashtable
    {
        memset(&lo, 0, sizeof(struct lo_data));

        lo.root.name    = resolved_rootdir_path;
        lo.root.ino     = FUSE_ROOT_ID;
        lo.root.nlookup = 2;
        lo.attr_valid   = 1.0f;

        lo.root.next = lo.root.prev = NULL;

        /* Initialise the hash table and assign */
	ret = hash_table_init(&lo.hash_table);

	if (ret == -1) {
            goto err_out;
	}

    }

    /* Initialise the spin lock for table */
    pthread_spin_init(&(lo.spinlock), 0);

    {
        struct fuse_session * se = NULL;


        se = fuse_session_new(&args, &ll_oper, sizeof(ll_oper), &lo);
        if (se == NULL)
            goto err_out1;

        if (fuse_set_signal_handlers(se) != 0)
            goto err_out2;

        if (fuse_session_mount(se, opts.mountpoint) != 0)
            goto err_out3;

        fuse_daemonize(opts.foreground);

        /* Block until ctrl+c or fusermount -u */
        if (opts.singlethread) {
            ret = fuse_session_loop(se);
        } else {
            ret = fuse_session_loop_mt(se, opts.clone_fd);
        }

        (void) ret;

err_out3:
        fuse_session_unmount(se);
err_out2:
        fuse_remove_signal_handlers(se);
err_out1:
        fuse_session_destroy(se);
    }

err_out:
    /* destroy the lock protecting the hash table */
    pthread_spin_destroy(&(lo.spinlock));

    /* free the arguments */
    fuse_opt_free_args(&args);

    /* free up the hash table */
    free_hash_table(&lo);

    /* destroy the hash table */
    hash_table_destroy(&lo.hash_table);

    free(resolved_rootdir_path);

    return ret;
}
