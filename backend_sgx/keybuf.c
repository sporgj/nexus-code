#include "internal.h"

void
key_buffer_init(struct nexus_key_buffer * key_buffer)
{
    memset(key_buffer, 0, sizeof(struct nexus_key_buffer));
}

int
key_buffer_put(struct nexus_key_buffer * key_buffer, struct nexus_key * key)
{
    char * tmp_str = NULL;

    tmp_str = nexus_key_to_str(key);

    if (tmp_str == NULL) {
        log_error("could not write key to buffer\n");
        return -1;
    }

    // generate the key buffer data
    key_buffer->key_type = key->type;

    key_buffer->key_str  = tmp_str;

    key_buffer->key_len  = strlen(tmp_str);

    return 0;
}

void
key_buffer_free(struct nexus_key_buffer * key_buffer)
{
    nexus_free(key_buffer->key_str);
}

int
key_buffer_derive(struct nexus_key_buffer * key_buffer, struct nexus_key * key)
{
    return __nexus_key_from_str(key, key_buffer->key_type, key_buffer->key_str);
}
