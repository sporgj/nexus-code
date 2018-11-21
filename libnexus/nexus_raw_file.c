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
    size_t        file_size = 0;
    FILE        * file_ptr  = NULL;

    struct stat   file_stats;

    int ret = 0;


    ret = stat(path, &file_stats);

    if (ret == -1) {
	log_error("Could not stat file (%s)\n", path);
	return -1;
    }

    file_size = file_stats.st_size;

    if (file_size <= 0) {
	*size = 0;
	*buf = nexus_malloc(1);

	return 0;
    }

    file_ptr  = fopen(path, "rb");

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
nexus_touch_raw_file(char * filepath)
{
    int fd = open(filepath, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (fd < 0) {
        log_error("could not create file (%s)\n", filepath);
        return -1;
    }

    close(fd);

    return 0;
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

