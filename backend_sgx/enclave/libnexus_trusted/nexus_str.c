#include "nexus_str.h"
#include "nexus_util.h"
#include "nexus_log.h"


static struct nexus_string *
__nexus_string_from_buf(char * str, size_t len)
{
    struct nexus_string * nexus_str = NULL;

    nexus_str = nexus_malloc(sizeof(struct nexus_string) + len + 1);

    nexus_str->_sz = len;
    memcpy(&nexus_str->_str, str, len);

    return nexus_str;
}

struct nexus_string *
nexus_string_from_str(char * str)
{
    return __nexus_string_from_buf(str, strlen(str));
}

void
nexus_string_free(struct nexus_string * nexus_str)
{
    nexus_free(nexus_str);
}

size_t
nexus_string_buf_size(struct nexus_string * nexus_str)
{
    return sizeof(struct nexus_string) + nexus_str->_sz;
}

uint8_t *
nexus_string_to_buf(struct nexus_string * nexus_str, uint8_t * buffer, size_t buflen)
{
    size_t nexus_str_buflen = nexus_string_buf_size(nexus_str);

    if (nexus_str_buflen > buflen) {
        return NULL;
    }

    memcpy(buffer, (uint8_t *)nexus_str, nexus_str_buflen);
    return (buffer + nexus_str_buflen);
}

struct nexus_string *
nexus_string_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_ptr)
{
    struct nexus_string * tmp_nexus_str = (struct nexus_string *)buffer;

    size_t tmp_nexus_str_len = nexus_string_buf_size(tmp_nexus_str);

    if (tmp_nexus_str_len > buflen) {
        log_error(
            "could not parse nexus_str. tmp_len=%zu, buflen=%zu\n", tmp_nexus_str_len, buflen);
        return NULL;
    }

    *output_ptr = (buffer + tmp_nexus_str_len);

    return __nexus_string_from_buf(tmp_nexus_str->_str, tmp_nexus_str->_sz);
}
