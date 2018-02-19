/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. This implementation is a little more sophisticated
 * than the one in passthrough.c, so performance is not quite as bad.
 *
 * Compile with:
 *
 *     gcc -Wall passthrough_fh.c `pkg-config fuse3 --cflags --libs` -lulockmgr -o passthrough_fh
 *
 * ## Source code ##
 * \include passthrough_fh.c
 */

#define FUSE_USE_VERSION 31

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fuse.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <sys/file.h> /* flock(2) */

#include "internal.h"


static char *
__get_fullpath(const char * path)
{
    char * fullpath = nexus_malloc(PATH_MAX);

    int ret = -1;

    ret = snprintf(fullpath, PATH_MAX, "%s/%s", volume_path, path);

    if (ret <= 0) {
        nexus_free(fullpath);
        log_error("error encoding path (%s)\n", path);
        abort();
    }

    return fullpath;
}

static void *
xmp_init(struct fuse_conn_info * conn, struct fuse_config * cfg)
{
    (void)conn;
    cfg->use_ino     = 1;
    cfg->nullpath_ok = 1;

    /* Pick up changes from lower filesystem right away. This is
       also necessary for better hardlink support. When the kernel
       calls the unlink() handler, it does not know the inode of
       the to-be-removed entry and can therefore not invalidate
       the cache of the associated inode - resulting in an
       incorrect st_nlink value being reported for any remaining
       hardlinks to this inode. */
    cfg->entry_timeout    = 0;
    cfg->attr_timeout     = 0;
    cfg->negative_timeout = 0;

    return NULL;
}

static int
xmp_getattr(const char * path, struct stat * stbuf, struct fuse_file_info * fi)
{
    int res;

    (void)path;

    char * fullpath = __get_fullpath(path);

    if (fi)
        res = fstat(fi->fh, stbuf);
    else
        res = lstat(fullpath, stbuf);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_access(const char * path, int mask)
{
    int res;

    char * fullpath = __get_fullpath(path);

    res = access(fullpath, mask);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_readlink(const char * path, char * buf, size_t size)
{
    int res;

    char * fullpath = __get_fullpath(path);

    res = readlink(fullpath, buf, size - 1);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

struct xmp_dirp {
    DIR *           dp;
    struct dirent * entry;
    off_t           offset;
};

static int
xmp_opendir(const char * path, struct fuse_file_info * fi)
{
    int               res;

    char * fullpath = __get_fullpath(path);

    struct xmp_dirp * d = malloc(sizeof(struct xmp_dirp));
    if (d == NULL)
        return -ENOMEM;

    d->dp = opendir(fullpath);

    nexus_free(fullpath);

    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
    }
    d->offset = 0;
    d->entry  = NULL;

    fi->fh = (unsigned long)d;
    return 0;
}

static inline struct xmp_dirp *
get_dirp(struct fuse_file_info * fi)
{
    return (struct xmp_dirp *)(uintptr_t)fi->fh;
}

static int
xmp_readdir(const char *            path,
            void *                  buf,
            fuse_fill_dir_t         filler,
            off_t                   offset,
            struct fuse_file_info * fi,
            enum fuse_readdir_flags flags)
{
    struct xmp_dirp * d = get_dirp(fi);

    (void)path;
    if (offset != d->offset) {
#ifndef __FreeBSD__
        seekdir(d->dp, offset);
#else
        /* Subtract the one that we add when calling
           telldir() below */
        seekdir(d->dp, offset - 1);
#endif
        d->entry  = NULL;
        d->offset = offset;
    }
    while (1) {
        struct stat              st;
        off_t                    nextoff;
        enum fuse_fill_dir_flags fill_flags = 0;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry)
                break;
        }
#ifdef HAVE_FSTATAT
        if (flags & FUSE_READDIR_PLUS) {
            int res;

            res = fstatat(dirfd(d->dp), d->entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
            if (res != -1)
                fill_flags |= FUSE_FILL_DIR_PLUS;
        }
#endif
        if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
            memset(&st, 0, sizeof(st));
            st.st_ino  = d->entry->d_ino;
            st.st_mode = d->entry->d_type << 12;
        }
        nextoff = telldir(d->dp);
#ifdef __FreeBSD__
        /* Under FreeBSD, telldir() may return 0 the first time
           it is called. But for libfuse, an offset of zero
           means that offsets are not supported, so we shift
           everything by one. */
        nextoff++;
#endif
        if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags))
            break;

        d->entry  = NULL;
        d->offset = nextoff;
    }

    return 0;
}

static int
xmp_releasedir(const char * path, struct fuse_file_info * fi)
{
    struct xmp_dirp * d = get_dirp(fi);
    (void)path;
    closedir(d->dp);
    free(d);
    return 0;
}

static int
xmp_mknod(const char * path, mode_t mode, dev_t rdev)
{
    int res;

    char * fullpath = __get_fullpath(path);

    if (S_ISFIFO(mode))
        res = mkfifo(fullpath, mode);
    else
        res = mknod(fullpath, mode, rdev);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_mkdir(const char * path, mode_t mode)
{
    int res;

    char * fullpath = __get_fullpath(path);

    res = mkdir(fullpath, mode);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_unlink(const char * path)
{
    int res;

    char * fullpath = __get_fullpath(path);

    res = unlink(fullpath);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_rmdir(const char * path)
{
    int res;

    char * fullpath = __get_fullpath(path);

    res = rmdir(fullpath);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_symlink(const char * from, const char * to)
{
    int res;

    // TODO
    if (1) {
        log_error("symlink operation not implemented\n");
        return -1;
    }

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_rename(const char * from, const char * to, unsigned int flags)
{
    int res;

    /* When we have renameat2() in libc, then we can implement flags */
    if (flags)
        return -EINVAL;

    // TODO
    if (1) {
        log_error("symlink operation not implemented\n");
        return -1;
    }

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_link(const char * from, const char * to)
{
    int res;

    // TODO
    if (1) {
        log_error("hardlink operation not implemented\n");
        return -1;
    }

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_chmod(const char * path, mode_t mode, struct fuse_file_info * fi)
{
    int res;

    char * fullpath = __get_fullpath(path);

    if (fi)
        res = fchmod(fi->fh, mode);
    else
        res = chmod(fullpath, mode);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_chown(const char * path, uid_t uid, gid_t gid, struct fuse_file_info * fi)
{
    int res;

    char * fullpath = __get_fullpath(path);

    if (fi)
        res = fchown(fi->fh, uid, gid);
    else
        res = lchown(fullpath, uid, gid);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_truncate(const char * path, off_t size, struct fuse_file_info * fi)
{
    int res;

    char * fullpath = __get_fullpath(path);

    if (fi)
        res = ftruncate(fi->fh, size);
    else
        res = truncate(fullpath, size);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
static int
xmp_utimens(const char * path, const struct timespec ts[2], struct fuse_file_info * fi)
{
    int res;

    char * fullpath = __get_fullpath(path);

    /* don't use utime/utimes since they follow symlinks */
    if (fi)
        res = futimens(fi->fh, ts);
    else
        res = utimensat(0, fullpath, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int
xmp_create(const char * path, mode_t mode, struct fuse_file_info * fi)
{
    int fd;

    char * fullpath = __get_fullpath(path);

    fd = open(fullpath, fi->flags, mode);

    nexus_free(fullpath);

    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int
xmp_open(const char * path, struct fuse_file_info * fi)
{
    int fd;

    char * fullpath = __get_fullpath(path);

    fd = open(fullpath, fi->flags);

    nexus_free(fullpath);

    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int
xmp_read(const char * path, char * buf, size_t size, off_t offset, struct fuse_file_info * fi)
{
    int res;

    (void)path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int
xmp_read_buf(const char *            path,
             struct fuse_bufvec **   bufp,
             size_t                  size,
             off_t                   offset,
             struct fuse_file_info * fi)
{
    struct fuse_bufvec * src;

    (void)path;

    src = malloc(sizeof(struct fuse_bufvec));
    if (src == NULL)
        return -ENOMEM;

    *src = FUSE_BUFVEC_INIT(size);

    src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    src->buf[0].fd    = fi->fh;
    src->buf[0].pos   = offset;

    *bufp = src;

    return 0;
}

static int
xmp_write(
    const char * path, const char * buf, size_t size, off_t offset, struct fuse_file_info * fi)
{
    int res;

    (void)path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int
xmp_write_buf(const char * path, struct fuse_bufvec * buf, off_t offset, struct fuse_file_info * fi)
{
    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

    (void)path;

    dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    dst.buf[0].fd    = fi->fh;
    dst.buf[0].pos   = offset;

    return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int
xmp_statfs(const char * path, struct statvfs * stbuf)
{
    int res;

    char * fullpath = __get_fullpath(path);

    res = statvfs(fullpath, stbuf);

    nexus_free(fullpath);

    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_flush(const char * path, struct fuse_file_info * fi)
{
    int res;

    (void)path;
    /* This is called from every close on an open file, so call the
       close on the underlying filesystem.	But since flush may be
       called multiple times for an open file, this must not really
       close the file.  This is important if used on a network
       filesystem like NFS which flush the data/metadata on close() */
    res = close(dup(fi->fh));
    if (res == -1)
        return -errno;

    return 0;
}

static int
xmp_release(const char * path, struct fuse_file_info * fi)
{
    (void)path;
    close(fi->fh);

    return 0;
}

static int
xmp_fsync(const char * path, int isdatasync, struct fuse_file_info * fi)
{
    int res;
    (void)path;

#ifndef HAVE_FDATASYNC
    (void)isdatasync;
#else
    if (isdatasync)
        res = fdatasync(fi->fh);
    else
#endif
    res = fsync(fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int
xmp_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info * fi)
{
    (void)path;

    if (mode)
        return -EOPNOTSUPP;

    return -posix_fallocate(fi->fh, offset, length);
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int
xmp_setxattr(const char * path, const char * name, const char * value, size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int
xmp_getxattr(const char * path, const char * name, char * value, size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int
xmp_listxattr(const char * path, char * list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int
xmp_removexattr(const char * path, const char * name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_LIBULOCKMGR
static int
xmp_lock(const char * path, struct fuse_file_info * fi, int cmd, struct flock * lock)
{
    (void)path;

    return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner, sizeof(fi->lock_owner));
}
#endif

static int
xmp_flock(const char * path, struct fuse_file_info * fi, int op)
{
    int res;
    (void)path;

    res = flock(fi->fh, op);
    if (res == -1)
        return -errno;

    return 0;
}

static struct fuse_operations xmp_oper = {
    .init       = xmp_init,
    .getattr    = xmp_getattr,
    .access     = xmp_access,
    .readlink   = xmp_readlink,
    .opendir    = xmp_opendir,
    .readdir    = xmp_readdir,
    .releasedir = xmp_releasedir,
    .mknod      = xmp_mknod,
    .mkdir      = xmp_mkdir,
    .symlink    = xmp_symlink,
    .unlink     = xmp_unlink,
    .rmdir      = xmp_rmdir,
    .rename     = xmp_rename,
    .link       = xmp_link,
    .chmod      = xmp_chmod,
    .chown      = xmp_chown,
    .truncate   = xmp_truncate,
#ifdef HAVE_UTIMENSAT
    .utimens = xmp_utimens,
#endif
    .create    = xmp_create,
    .open      = xmp_open,
    .read      = xmp_read,
    .read_buf  = xmp_read_buf,
    .write     = xmp_write,
    .write_buf = xmp_write_buf,
    .statfs    = xmp_statfs,
    .flush     = xmp_flush,
    .release   = xmp_release,
    .fsync     = xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
    .fallocate = xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
    .setxattr    = xmp_setxattr,
    .getxattr    = xmp_getxattr,
    .listxattr   = xmp_listxattr,
    .removexattr = xmp_removexattr,
#endif
#ifdef HAVE_LIBULOCKMGR
    .lock = xmp_lock,
#endif
    .flock = xmp_flock,
};

int
start_fuse(struct fuse_args * args)
{
    umask(0);
    return fuse_main(args->argc, args->argv, &xmp_oper, NULL);
}
