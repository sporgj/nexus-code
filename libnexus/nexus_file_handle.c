#include <stdio.h>
#include <string.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/limits.h>

#include "nexus_util.h"
#include "nexus_log.h"
#include "nexus_raw_file.h"
#include "nexus_file_handle.h"


#define MAX_RETRIES     10

#define POSIX_OPEN_MODE     (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)


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

    file_handle->fd = open(filepath, __get_sysopen_flags(mode), POSIX_OPEN_MODE);

    if (file_handle->fd < 0) {
        nexus_free(file_handle);
        log_error("could not open file (%s)\n", filepath);
        perror("could not open:");
        return NULL;
    }

    if (mode & NEXUS_FWRITE) {
        int tries = 0;

try_lock:
        if (flock(file_handle->fd, LOCK_EX)) {
            log_error("could not lock file [try=%d] (%s)\n", tries, filepath);
            perror("strerror: ");

            if (tries < MAX_RETRIES) {
                tries += 1;
                goto try_lock;
            }

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

void
nexus_file_handle_close(struct nexus_file_handle * file_handle)
{
    if (file_handle->is_locked) {
        flock(file_handle->fd, LOCK_UN);
    }

    close(file_handle->fd);

    nexus_free(file_handle->filepath);

    nexus_free(file_handle);
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
