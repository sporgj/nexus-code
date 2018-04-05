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



struct nexus_raw_file *
nexus_acquire_raw_file(char * filepath)
{
    struct nexus_raw_file * raw_file = NULL;

    raw_file = nexus_malloc(sizeof(struct nexus_raw_file));

    raw_file->file_ptr = fopen(filepath, "wb");

    if (raw_file->file_ptr == NULL) {
	log_error("could not open file (%s)\n", filepath);

	nexus_free(raw_file);
	return NULL;
    }

    if (flock(fileno(raw_file->file_ptr), LOCK_EX)) {
	fclose(raw_file->file_ptr);
	nexus_free(raw_file);

        log_error("could not lock file (%s)", filepath);
	return NULL;
    }

    raw_file->filepath = strndup(filepath, PATH_MAX);

    return raw_file;
}

void
nexus_release_raw_file(struct nexus_raw_file * raw_file)
{
    if (raw_file == NULL) {
	return;
    }

    fclose(raw_file->file_ptr); // closing the file should release the lock

    nexus_free(raw_file->filepath);

    nexus_free(raw_file);
}

int
nexus_update_raw_file(struct nexus_raw_file * raw_file, uint8_t * buf, size_t size)
{
    int nbytes = fwrite(buf, 1, size, raw_file->file_ptr);

    if (nbytes != (int) size) {
        log_error("could not write file (%s). tried=%d, actual=%d\n",
                  raw_file->filepath,
                  (int)size,
                  nbytes);
        return -1;
    }

    return 0;
}



int
nexus_read_raw_file(char     * path,
		    uint8_t ** buf,
		    size_t   * size)
{
    FILE        * file_ptr = NULL;
    struct stat   file_stats;
    
    size_t        file_size  = 0;
    uint8_t     * file_data = NULL;
    
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


    file_data = nexus_malloc(file_size + 1); // We add an extra byte here to make sure strings are NULL terminated

    file_ptr  = fopen(path, "rb");

    if (file_ptr == NULL) {
        log_error("Could not open file (%s)\n", path);
	goto out;
    }

    ret = fread(file_data, file_size, 1, file_ptr);

    ret--; /* This is a funky op to make the ret value be correct 
	    * fread will return 1 on success, and 0 on error (see fread man page)
	    */

    if (ret == -1) {
	nexus_free(file_data);
	goto out;
    }

    *buf  = file_data;
    *size = file_size;
    
 out:
    fclose(file_ptr);
    
    return ret;
}



int
nexus_write_raw_file(char   * path,
		     void   * buf,
		     size_t   size)
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
    FILE * fd = NULL;

    fd = fopen(filepath, "wb");

    if (fd == NULL) {
	log_error("could not create file (%s)\n", filepath);
	return -1;
    }

    fclose(fd);

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
delete_fn(const char        * fpath,
	  const struct stat * sb,
	  int                 typeflag,
	  struct FTW        * ftwbuf)
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

