#pragma once

#include <stdint.h>

int
nexus_read_raw_file(char * path, uint8_t ** buf, size_t * size);


int
nexus_write_raw_file(char * path, void * buf, size_t len);


int
nexus_create_raw_file(char * path);


int
nexus_delete_raw_file(char * path);
