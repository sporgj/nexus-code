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


static char *
__get_fopen_str_flags(nexus_io_flags_t mode)
{
    if (mode & NEXUS_FREAD) {
        if (mode & NEXUS_FWRITE) {
            return "rb+";
        }

        return "rb";
    }

    return "wb";
}

#define MAX_RETRIES 10

struct nexus_file_handle *
nexus_file_handle_open(char * filepath, nexus_io_flags_t mode)
{
    struct nexus_file_handle * file_handle = nexus_malloc(sizeof(struct nexus_file_handle));

    file_handle->file_ptr = fopen(filepath, __get_fopen_str_flags(mode));

    if (file_handle->file_ptr == NULL) {
        log_error("could not open file (%s)\n", filepath);
        goto out;
    }

    if (mode & NEXUS_FWRITE) {
        int tries = 0;

try_lock:
        if (flock(fileno(file_handle->file_ptr), LOCK_EX)) {
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
    if (file_handle->file_ptr) {
        fclose(file_handle->file_ptr);
    }

    nexus_free(file_handle);

    return NULL;
}

void
nexus_file_handle_close(struct nexus_file_handle * file_handle)
{
    if (file_handle->is_locked) {
        flock(fileno(file_handle->file_ptr), LOCK_UN);
    }

    fclose(file_handle->file_ptr);

    nexus_free(file_handle->filepath);

    nexus_free(file_handle);
}

int
nexus_file_handle_read(struct nexus_file_handle * file_handle, uint8_t ** p_buf, size_t * p_size)
{
    uint8_t * buf = NULL;

    int size      = 0;
    int nbytes    = 0;

    {
        fseek(file_handle->file_ptr, 0, SEEK_END);
        size = ftell(file_handle->file_ptr);
        rewind(file_handle->file_ptr);
    }

    buf = nexus_malloc(size);

    nbytes = fread(buf, 1, size, file_handle->file_ptr);

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
        rewind(file_handle->file_ptr);
    }

    // only reopen the file if opened in read mode
    file_handle->touched  = true;

    nbytes = fwrite(buf, 1, size, file_handle->file_ptr);

    if (nbytes != (int) size) {
        log_error("could not write file (%s). tried=%d, actual=%d\n",
                  file_handle->filepath,
                  (int)size,
                  nbytes);
        return -1;
    }

    if (ftruncate(fileno(file_handle->file_ptr), size)) {
        log_error("could not truncate file (%s, size=%zu)\n", file_handle->filepath, size);
        return -1;
    }

    return 0;
}


int
nexus_file_handle_flush(struct nexus_file_handle * file_handle)
{
    return fflush(file_handle->file_ptr);
}
