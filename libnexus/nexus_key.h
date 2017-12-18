#pragma once

#include <stdint.h>
#include <stdio.h>

typedef enum {
    NEXUS_SGX_SEALED_KEY,
    NEXUS_RSA_2048

} nexus_key_type_t;

struct nexus_key {
    uint8_t * data;
    size_t    key_size;
};
    




struct nexus_key * 
nexus_load_key_from_file(char * key_path);

struct nexus_key *
nexus_create_key(nexus_key_type_t type);

void
nexus_free_key(struct nexus_key * key);



int    nexus_key_from_base64(struct nexus_key * key, char * base64_str);
char * nexus_key_to_base64(struct nexus_key * key);
