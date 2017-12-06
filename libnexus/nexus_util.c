#include <uuid/uuid.h>

#include "nexus_internal.h"
#include "base58.h"

int
read_file(const char * fpath, uint8_t ** p_buffer, size_t * p_size)
{
    int       ret    = -1;
    ssize_t   size   = 0;
    ssize_t   nbytes = 0;
    uint8_t * buffer = NULL;
    FILE *    fd     = NULL;

    fd = fopen(fpath, "rb");
    if (fd == NULL) {
        log_error("fopen(%s) FAILED", fpath);
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    if (size == -1) {
        log_error("ftell returned -1");
        goto out;
    }
    fseek(fd, 0, SEEK_SET);

    buffer = (uint8_t *)calloc(1, size);
    if (buffer == NULL) {
        log_error("allocation error (bytes=%zu)", size);
        goto out;
    }

    nbytes = fread(buffer, 1, size, fd);
    if (nbytes != size) {
        log_error("fread FAILED. tried=%zu, got=%zu", size, nbytes);
        goto out;
    }

    *p_buffer = buffer;
    *p_size   = size;

    ret = 0;
out:
    fclose(fd);

    if (ret) {
        if (buffer) {
            nexus_free(buffer);
        }
    }

    return ret;
}

int
write_file(const char * fpath, void * buffer, size_t size)
{
    int    ret    = -1;
    size_t nbytes = 0;
    FILE * fd     = NULL;

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
        log_error("fopen(%s) FAILED", fpath);
        return -1;
    }

    nbytes = fwrite(buffer, 1, size, fd);
    if (nbytes != size) {
        log_error("fwrite FAILED. tried=%zu, got=%zu", size, nbytes);
        goto out;
    }

    ret = 0;
out:
    fclose(fd);
    return ret;
}

char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max)
{
    size_t len1  = strnlen(dest, max);
    size_t len2  = (join == NULL) ? 0 : strnlen(join, max);
    size_t len3  = strnlen(src, max);
    size_t total = len1 + len2 + len3;

    if (total > max) {
        // XXX should we report here??
        return NULL;
    }

    char * result = realloc(dest, total + 1);
    if (result == NULL) {
        log_error("allocation error");
        return NULL;
    }

    if (join != NULL) {
        memcpy(result + len1, join, len2);
    }

    memcpy(result + len1 + len2, src, len3);
    result[total] = '\0';

    return result;
}

char *
my_strncat(char * dest, const char * src, size_t max)
{
    return my_strnjoin(dest, NULL, src, max);
}

char *
uuid_to_string(struct uuid * uuid)
{
    char * buffer = NULL;
    size_t size   = base58_encoded_size(sizeof(struct uuid));

    buffer = (char *)calloc(1, size);
    if (buffer == NULL) {
        log_error("allocation error");
        return NULL;
    }

    base58_encode((uint8_t *)buffer, (uint8_t *)uuid, sizeof(struct uuid));

    return buffer;
}

char *
filepath_from_name(char * directory, const char * filename)
{
    return my_strnjoin(directory, "/", filename, PATH_MAX);
}

// XXX check for allocations
char *
filepath_from_uuid(const char * dir_path, struct uuid * uuid)
{
    char * fname    = NULL;
    char * fullpath = NULL;

    fname = uuid_to_string(uuid);
    if (fname == NULL) {
        log_error("allocation error");
        return NULL;
    }

    fullpath = strndup(dir_path, PATH_MAX);
    fullpath = filepath_from_name(fullpath, fname);
    free(fname);

    if (fullpath == NULL) {
        log_error("allocation error");
        return NULL;
    }

    return fullpath;
}
