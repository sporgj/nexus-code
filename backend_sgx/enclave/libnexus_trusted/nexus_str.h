#pragma once

#include <stdint.h>
#include <stdlib.h>


struct nexus_string {
    uint16_t    _sz;
    char        _str[0];
};


struct nexus_string *
nexus_string_from_str(char * str);

void
nexus_string_free(struct nexus_string * nexus_str);

// writes to the buffer, and returns the pointer advance
uint8_t *
nexus_string_to_buf(struct nexus_string * nexus_str, uint8_t * buffer, size_t buflen);

struct nexus_string *
nexus_string_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** outptr_ptr);

size_t
nexus_string_buf_size(struct nexus_string * nexus_str);

