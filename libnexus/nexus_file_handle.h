#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "nexus_fs.h"


struct nexus_file_handle {
    FILE            * file_ptr;
    char            * filepath;
    nexus_io_flags_t   mode;
    bool              touched;
};

/**
 * Creates a new file handle
 * @param filepath
 * @param mode
 */
struct nexus_file_handle *
nexus_file_handle_open(char * filepath, nexus_io_flags_t mode);

void
nexus_file_handle_close(struct nexus_file_handle * file_handle);

int
nexus_file_handle_read(struct nexus_file_handle * file_handle, uint8_t ** p_buf, size_t * p_size);

int
nexus_file_handle_write(struct nexus_file_handle * file_handle, uint8_t * buf, size_t size);

int
nexus_file_handle_flush(struct nexus_file_handle * file_handle);
