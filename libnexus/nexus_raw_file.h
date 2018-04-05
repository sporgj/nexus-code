/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>
#include <stdio.h>



struct nexus_raw_file {
    FILE * file_ptr;
    char * filepath;
};


/**
 * Opens a file and acquires a lock
 * @param filepath
 * @return NULL on failure
 */
struct nexus_raw_file *
nexus_acquire_raw_file(char * filepath);

/**
 * Releases the acquired raw file
 * @param raw_file
 */
void
nexus_release_raw_file(struct nexus_raw_file * raw_file);

/**
 * Updates the raw file
 * @param raw_file is the nexus_raw_file
 * @return 0 on success
 */
int
nexus_update_raw_file(struct nexus_raw_file * raw_file, uint8_t * buf, size_t size);



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
