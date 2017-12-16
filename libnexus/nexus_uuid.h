#pragma once


#define NEXUS_UUID_SIZE  16

struct nexus_uuid {
    uint8_t raw[NEXUS_UUID_SIZE];
};


int nexus_uuid_gen(struct nexus_uuid * uuid);


char * nexus_uuid_to_base64(struct nexus_uuid * uuid);
int    nexus_uuid_from_base64(struct nexus_uuid * uuid, char * base64_str);
