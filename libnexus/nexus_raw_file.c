/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ftw.h>

#include <linux/limits.h>
#include <sys/wait.h>

#include <nexus_raw_file.h>
#include <nexus_util.h>
#include <nexus_log.h>

int
__nexus_read_raw_file(FILE * file_ptr, size_t file_size, uint8_t ** buf, size_t * size)
{
    uint8_t * file_data = NULL;

    // We add an extra byte here to make sure strings are NULL terminated
    file_data = nexus_malloc(file_size + 1);

    if (fread(file_data, file_size, 1, file_ptr) != 1) {
        nexus_free(file_data);
        return -1;
    }

    *buf  = file_data;
    *size = file_size;

    return 0;
}

int
nexus_read_raw_file(char * path, uint8_t ** buf, size_t * size)
{
    size_t file_size = 0;
    FILE * file_ptr  = NULL;

    struct stat file_stats;

    int ret = 0;

    ret = stat(path, &file_stats);

    if (ret == -1) {
        log_error("Could not stat file (%s)\n", path);
        return -1;
    }

    file_size = file_stats.st_size;

    if (file_size <= 0) {
        *size = 0;
        *buf  = nexus_malloc(1);

        return 0;
    }

    file_ptr = fopen(path, "rb");

    if (file_ptr == NULL) {
        log_error("Could not open file (%s)\n", path);
        goto out;
    }

    ret = __nexus_read_raw_file(file_ptr, file_size, buf, size);
out:
    fclose(file_ptr);

    return ret;
}

int
nexus_write_raw_file(char * path, void * buf, size_t size)
{
    FILE * file_ptr = NULL;

    int ret = 0;

    file_ptr = fopen(path, "wb");

    if (file_ptr == NULL) {
        log_error("Failed top open file (%s)\n", path);
        return -1;
    }

    ret = fwrite(buf, size, 1, file_ptr);

    ret--; /* This is a funky op to make the ret value be correct
            * fread will return 1 on success, and 0 on error (see fwrite man page)
            */

    if (ret == -1) {
        log_error("Failed to write file (%s) (size=%zu)", path, size);
    }

    fclose(file_ptr);

    return ret;
}

int
nexus_touch_raw_file2(char * filepath, mode_t mode)
{
    int fd = open(filepath, O_CREAT, mode);

    if (fd < 0) {
        log_error("could not create file (%s)\n", filepath);
        return -1;
    }

    close(fd);

    return 0;
}

int
nexus_touch_raw_file(char * filepath)
{
    return nexus_touch_raw_file2(filepath, NEXUS_POSIX_OPEN_MODE);
}

int
nexus_delete_raw_file(char * path)
{
    int ret = 0;

    ret = unlink(path);

    if (ret == -1) {
        log_error("Could not delete file (%s)\n", path);
    }

    return ret;
}

static int
delete_fn(const char * fpath, const struct stat * sb, int typeflag, struct FTW * ftwbuf)
{
    log_debug("Deleting: %s\n", fpath);

    return remove(fpath);
}




int
nexus_delete_path(char * path)
{

    int ret = 0;

    log_debug("Deleting Path: %s\n", path);

    ret = nftw(path, delete_fn, 20, FTW_DEPTH);

    return ret;
}


#if 0
// TODO: remove this, old artifact
static int
__copy_file_using_bash(const char * src_filepath, const char * dst_filepath)
{
    int status = 0;

    pid_t pid = fork();

    if (pid < 0) {
        perror("failure");
        return -1;
    }

    if (pid == 0) {
        execlp("cp", "cp", "-p", src_filepath, dst_filepath, NULL);
        perror("exec() FAILURE\n");
        _exit(1);
    }

    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid()");
        return -1;
    }

    return status;
}
#endif

static int
__copy_file_using_libc(const char * src_filepath, const char * dst_filepath, struct stat * src_stat)
{
    static int tmp_buflen = 4096;
    uint8_t *  tmp_buffer = NULL;

    struct stat tmp_stat;

    int src_fd = -1;
    int dst_fd = -1;


    src_fd = open(src_filepath, O_RDONLY);
    if (src_fd == -1) {
        log_error("could not open source file (%s)\n", src_filepath);
        return -1;
    }

    if (src_stat == NULL) {
        src_stat = &tmp_stat;

        if (fstat(src_fd, src_stat)) {
            log_error("could not stat (%s)\n", src_filepath);
            close(src_fd);
            return -1;
        }
    }

    dst_fd = open(dst_filepath, O_CREAT | O_WRONLY | O_TRUNC, src_stat->st_mode);
    if (dst_fd == -1) {
        close(src_fd);
        nexus_free(tmp_buffer);
        log_error("could not open destination file (%s)\n", dst_filepath);
        return -1;
    }


    tmp_buffer = nexus_malloc(tmp_buflen);

    while (1) {
        ssize_t read_bytes = read(src_fd, tmp_buffer, tmp_buflen);

        if (read_bytes == 0) {
            break;
        }

        if (read_bytes == -1) {
            log_error("error reading file (%s)\n", src_filepath);
            perror("__copy_file:");
            goto out_err;
        }

        ssize_t write_bytes = write(dst_fd, tmp_buffer, read_bytes);
        if (write_bytes != read_bytes) {
            log_error("wrting bytes failed. tried=%zd, got=%zd\n", read_bytes, write_bytes);
            goto out_err;
        }
    }

    nexus_free(tmp_buffer);

    close(src_fd);

    if (close(dst_fd)) {
        log_error("file (%s) closed with error\n", dst_filepath);
        return -1;
    }

    return 0;
out_err:
    if (tmp_buffer) {
        nexus_free(tmp_buffer);
    }

    close(src_fd);
    close(dst_fd);

    return -1;
}

int
nexus_copy_raw_file(const char * src_filepath, const char * dst_filepath, struct stat * src_stat)
{
    if (src_filepath == NULL || dst_filepath == NULL) {
        log_error("incorrect arguments\n");
        return -1;
    }

    return __copy_file_using_libc(src_filepath, dst_filepath, src_stat);
}


static int
__get_sysopen_flags(nexus_io_flags_t mode)
{
    int res = 0;

    if (mode & NEXUS_FREAD) {
        if (mode & NEXUS_FWRITE) {
            res = O_RDWR | O_EXCL;
        } else {
            res = O_RDONLY;
        }
    } else if (mode & NEXUS_FWRITE) {
        res = O_WRONLY;
    }

    // by POSIX standards, having O_EXCL and O_CREAT will result in a fail
    // if the file exists.
    if (mode & NEXUS_FCREATE) {
        res |= (O_CREAT | O_WRONLY) & (~O_EXCL);  // you can't have both O_CREAT and O_EXCL
    }

    return res;
}

struct nexus_file_handle *
nexus_file_handle_open(char * filepath, nexus_io_flags_t mode)
{
    struct nexus_file_handle * file_handle = nexus_malloc(sizeof(struct nexus_file_handle));

    file_handle->fd = open(filepath, __get_sysopen_flags(mode), NEXUS_POSIX_OPEN_MODE);

    if (file_handle->fd < 0) {
        nexus_free(file_handle);
        log_error("could not open file (%s)\n", filepath);
        return NULL;
    }

    if (mode & NEXUS_FWRITE) {
        if (flock(file_handle->fd, LOCK_EX)) {
            log_error("could not lock file (%s)\n", filepath);
            perror("strerror: ");

            goto out;
        }

        file_handle->is_locked = true;
    }

    file_handle->mode     = mode;
    file_handle->filepath = strndup(filepath, PATH_MAX);

    return file_handle;
out:
    close(file_handle->fd);

    nexus_free(file_handle);

    return NULL;
}

int
nexus_file_handle_close(struct nexus_file_handle * file_handle)
{
    int ret = close(file_handle->fd);

    if (ret) {
        log_error("closing (%s) completed with error\n", file_handle->filepath);
        perror("handle_close:");
    }

    nexus_free(file_handle->filepath);

    nexus_free(file_handle);

    return ret;
}

int
nexus_file_handle_read(struct nexus_file_handle * file_handle, uint8_t ** p_buf, size_t * p_size)
{
    uint8_t * buf = NULL;

    int nbytes    = 0;
    int size      = lseek(file_handle->fd, 0, SEEK_END);

    if (size < 0) {
        log_error("could not seek to end of file\n");
    }


    lseek(file_handle->fd, 0, SEEK_SET);

    buf = nexus_malloc(size);

    nbytes = read(file_handle->fd, buf, size);

    file_handle->touched = true;

    if (nbytes != (int) size) {
        log_error("could not read file (%s). tried=%d, actual=%d\n",
                  file_handle->filepath,
                  (int)size,
                  nbytes);
        return -1;
    }

    *p_buf  = buf;
    *p_size = size;

    return 0;
}

int
nexus_file_handle_write(struct nexus_file_handle * file_handle, uint8_t * buf, size_t size)
{
    int nbytes = -1;

    if (file_handle->touched) {
        lseek(file_handle->fd, 0, SEEK_SET);
    }

    file_handle->touched  = true;

    nbytes = write(file_handle->fd, buf, size);

    if (nbytes != (int) size) {
        log_error("could not write file (%s). tried=%d, actual=%d\n",
                  file_handle->filepath,
                  (int)size,
                  nbytes);
        return -1;
    }

    if (ftruncate(file_handle->fd, size)) {
        log_error("could not truncate file (%s, size=%zu)\n", file_handle->filepath, size);
        return -1;
    }

    return 0;
}


int
nexus_file_handle_flush(struct nexus_file_handle * file_handle)
{
    return fsync(file_handle->fd);
}
