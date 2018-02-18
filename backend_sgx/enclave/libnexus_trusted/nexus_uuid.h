/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#pragma once

#include <stdint.h>
#include <stdbool.h>


#define NEXUS_UUID_SIZE  16

struct nexus_uuid {
    uint8_t raw[NEXUS_UUID_SIZE];
};

struct nexus_uuid_path {
    size_t count;
    struct nexus_uuid uuids[0];
};


int nexus_uuid_gen(struct nexus_uuid * uuid);

int
nexus_uuid_compare(struct nexus_uuid * src_uuid, struct nexus_uuid * dst_uuid);

struct nexus_uuid * nexus_uuid_clone(struct nexus_uuid * uuid);

int
nexus_uuid_copy(struct nexus_uuid * src_uuid, struct nexus_uuid * dst_uuid);

char * nexus_uuid_to_base64(struct nexus_uuid * uuid);
int    nexus_uuid_from_base64(struct nexus_uuid * uuid, char * base64_str);

char * nexus_uuid_to_alt64(struct nexus_uuid * uuid);
int    nexus_uuid_from_alt64(struct nexus_uuid * uuid, char * alt64_str);

bool nexus_uuid_is_valid(struct nexus_uuid * uuid);
