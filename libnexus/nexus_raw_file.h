/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <sys/stat.h>

#include <stdint.h>
#include <stdio.h>

#include <nexus_fs.h>


struct nexus_file_handle {
    int               fd;
    char            * filepath;
    bool              is_locked;
    nexus_io_flags_t  mode;
    bool              touched;
};

/**
 * Creates a new file handle
 * @param filepath
 * @param mode
 */
struct nexus_file_handle *
nexus_file_handle_open(char * filepath, nexus_io_flags_t mode);

int
nexus_file_handle_close(struct nexus_file_handle * file_handle);

int
nexus_file_handle_read(struct nexus_file_handle * file_handle, uint8_t ** p_buf, size_t * p_size);

int
nexus_file_handle_write(struct nexus_file_handle * file_handle, uint8_t * buf, size_t size);

int
nexus_file_handle_flush(struct nexus_file_handle * file_handle);


int
__nexus_read_raw_file(FILE * file_ptr, size_t file_size, uint8_t ** buf, size_t * size);


int
nexus_read_raw_file(char * path, uint8_t ** buf, size_t * size);


int
nexus_write_raw_file(char * path, void * buf, size_t len);


/**
 * Creates an empty file
 * @param path
 * @return 0 on success
 */
int
nexus_touch_raw_file(char * path);

int
nexus_touch_raw_file2(char * path, mode_t mode);

/*
 * This will delete a single file
 *  path must point to a file (not a directory)
 */
int
nexus_delete_raw_file(char * path);



/*
 * This will recursively delete anything at or below the path location
 */
int
nexus_delete_path(char * path);


int
nexus_copy_raw_file(const char * src_filepath, const char * dst_filepath, struct stat * src_stat);
