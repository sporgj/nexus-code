#include <string.h>

#include "abac_internal.h"
#include "value.h"


struct __abac_value_buf {
    abac_value_type_t   type;
    size_t              size;
    uint8_t             data[0];
} __attribute__((packed));



void *
__abac_value_get_rawptr(struct abac_value * abac_value)
{
    return abac_value->raw_ptr;
}

size_t
abac_value_bufsize(struct abac_value * abac_value)
{
    return sizeof(struct __abac_value_buf) + abac_value->data_sz;
}

struct abac_value *
__abac_value_from_data(void * data, size_t size, abac_value_type_t value_type)
{
    struct abac_value * abac_value = nexus_malloc(sizeof(struct abac_value));

    abac_value->type    = value_type;
    abac_value->data_sz = size;
    abac_value->raw_ptr = data;

    return abac_value;
}

struct abac_value *
abac_value_shallow_copy(struct abac_value * abac_value)
{
    struct abac_value * new_abac_value = NULL;

    new_abac_value = __abac_value_from_data(abac_value->raw_ptr, abac_value->data_sz, abac_value->type);

    new_abac_value->is_shallow_copy = true;

    return new_abac_value;
}

void
abac_value_free(struct abac_value * abac_value)
{
    if (!(abac_value->is_shallow_copy) && (abac_value->type != ABAC_VALUE_NUMBER)) {
        nexus_free(abac_value->raw_ptr);
    }

    nexus_free(abac_value);
}

static inline struct abac_value *
__abac_value_from_str(char * string, bool is_identifier)
{
    size_t sz = strnlen(string, _ABAC_VALUE_MAXLEN);

    abac_value_type_t type = is_identifier ? ABAC_VALUE_IDENTIFIER : ABAC_VALUE_STRING;

    char * copy = nexus_malloc(sz + 1);
    memcpy(copy, string, sz);

    return __abac_value_from_data(copy, sz + 1, type);
}

struct abac_value *
abac_value_from_str(char * string)
{
    return __abac_value_from_str(string, false);
}

struct abac_value *
abac_value_from_str_as_identifier(char * string)
{
    return __abac_value_from_str(string, true);
}

struct abac_value *
abac_value_from_int(int intval)
{
    struct abac_value * abac_value = __abac_value_from_data(NULL, sizeof(int), ABAC_VALUE_NUMBER);

    abac_value->type    = ABAC_VALUE_NUMBER;
    abac_value->int_val = intval;

    return abac_value;
}


struct abac_value *
abac_value_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_ptr)
{
    struct abac_value       * abac_value      = nexus_malloc(sizeof(struct abac_value));
    struct __abac_value_buf * abac_val_buffer = (struct __abac_value_buf *)buffer;

    size_t minsize = sizeof(struct __abac_value_buf) + abac_val_buffer->size;

    if (buflen < minsize) {
        nexus_free(abac_value);
        log_error("buffer is too small for abac_value. min=%zu, buflen=%zu\n", minsize, buflen);
        return NULL;
    }

    abac_value->data_sz = abac_val_buffer->size;
    abac_value->type    = abac_val_buffer->type;

    uint8_t * src_buf   = buffer + sizeof(struct __abac_value_buf);
    abac_value->raw_ptr = nexus_malloc(abac_val_buffer->size);
    memcpy(abac_value->raw_ptr, src_buf, abac_value->data_sz);

    *output_ptr = (buffer + minsize);

    return abac_value;
}

uint8_t *
abac_value_to_buf(struct abac_value * abac_value, uint8_t * buffer, size_t buflen)
{
    struct __abac_value_buf * abac_val_buffer = (struct __abac_value_buf *)buffer;

    size_t minsize = abac_value_bufsize(abac_value);

    if (buflen < minsize) {
        log_error("buffer is too small for abac_value. min=%zu, buflen=%zu\n", minsize, buflen);
        return NULL;
    }

    abac_val_buffer->size = abac_value->data_sz;
    abac_val_buffer->type = abac_value->type;

    uint8_t * dest_buf = (buffer + sizeof(struct __abac_value_buf));
    memcpy(dest_buf, abac_value->raw_ptr, abac_value->data_sz);

    return (buffer + minsize);
}

char *
abac_value_stringify(struct abac_value * abac_value)
{
    if ((abac_value->type == ABAC_VALUE_STRING) || (abac_value->type == ABAC_VALUE_IDENTIFIER)) {
        return strndup(abac_value->str_val, abac_value->data_sz);
    } else if (abac_value->type == ABAC_VALUE_NUMBER) {
        char * buffer = nexus_malloc(10);
        snprintf(buffer, 10, "%d", abac_value->int_val);
        return buffer;
    }

    return NULL;
}

int
abac_value_as_datalog(struct abac_value * abac_value, rapidstring * string_builder, bool as_rule)
{
    char buffer[10] = { 0 };

    if (abac_value->type == ABAC_VALUE_STRING) {
        rs_cat_n(string_builder, "\"", 1);
        rs_cat(string_builder, abac_value->str_val);
        rs_cat_n(string_builder, "\"", 1);
    } else if (abac_value->type == ABAC_VALUE_IDENTIFIER) {
        // append 'u' or 'o'
        if (as_rule) {
            char c = abac_value->str_val[0];
            if (c == 'u') {
                rs_cat_n(string_builder, "U", 1);
            } else if (c == 'o') {
                rs_cat_n(string_builder, "O", 1);
            }
        } else {
            // append onlye
            rs_cat_n(string_builder, abac_value->str_val, 1);
        }

        // if we have a dot notation, split the argument
        if (abac_value->data_sz > 2) {
            rs_cat_n(string_builder, ", ", 2);
            rs_cat(string_builder, &abac_value->str_val[2]);
        }
    } else if (abac_value->type == ABAC_VALUE_NUMBER) {
        int n = snprintf(buffer, 10, "%d", abac_value->int_val);
        rs_cat_n(string_builder, buffer, n);
    } else {
        log_error("unknown abac value\n");
        return -1;
    }

    return 0;
}
