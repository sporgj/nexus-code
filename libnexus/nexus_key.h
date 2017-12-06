#pragma once

#include <stdint.h>
#include <stdio.h>

#define NEXUS_KEY_SIZE   16

struct nexus_key {
    uint8_t * data;
    size_t    key_size;
};
    


struct nexus_key * 
nexus_load_key_from_file(char * key_path);

void
nexus_free_key(struct nexus_key * key);
