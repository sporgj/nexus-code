#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <libnexus_trusted/rapidstring.h>

#define _ABAC_VALUE_MAXLEN      (1024)

typedef enum {
    ABAC_VALUE_STRING = 1,
    ABAC_VALUE_IDENTIFIER,   // works mostly like a string
    ABAC_VALUE_NUMBER,
} abac_value_type_t;


struct abac_value {
    abac_value_type_t type;

    bool              is_shallow_copy;

    size_t            data_sz;

    union {
        char        * str_val;
        int           int_val;
        void        * raw_ptr;
    };
};


void *
__abac_value_get_rawptr(struct abac_value * abac_value);


/**
 * Creates a new abac value from the specific
 */
struct abac_value *
__abac_value_from_data(void * data, size_t len, abac_value_type_t value_type);

struct abac_value *
abac_value_shallow_copy(struct abac_value * abac_value);

void
abac_value_free(struct abac_value * abac_value);


struct abac_value *
abac_value_from_str(char * string);

struct abac_value *
abac_value_from_str_as_identifier(char * string);

struct abac_value *
abac_value_from_int(int intval);


struct abac_value *
abac_value_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_ptr);

uint8_t *
abac_value_to_buf(struct abac_value * abac_value, uint8_t * buffer, size_t buflen);


size_t
abac_value_bufsize(struct abac_value * abac_value);


char *
abac_value_stringify(struct abac_value * abac_value);

int
abac_value_as_datalog(struct abac_value * abac_value, rapidstring * string_builder, bool as_rule);
