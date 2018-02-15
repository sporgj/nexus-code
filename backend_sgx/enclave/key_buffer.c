/**
 * Copyright (c) 2018, Judicael Djoko <jbriand@cs.pitt.edu>
 *
 * This manages the transfer of key related data between enclanve and non-enclave memory
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include "enclave_internal.h"


#define MAX_KEY_STR 1024


void
key_buffer_copy(struct nexus_key_buffer * src_buffer, struct nexus_key_buffer * dst_buffer)
{
    memcpy(dst_buffer, src_buffer, sizeof(struct nexus_key_buffer));
}

void
key_buffer_free(struct nexus_key_buffer * key_buffer)
{
    nexus_free(key_buffer);
}

struct nexus_key *
key_buffer_get(struct nexus_key_buffer * key_buffer, nexus_key_type_t raw_key_type)
{
    struct nexus_key * raw_key = NULL;

    struct nexus_key * protected_key = NULL;
    char             * protected_str = NULL;

    // get the sealed/wrapped version from the string
    protected_str = strndup(key_buffer->key_str, MAX_KEY_STR);

    protected_key = nexus_key_from_str(key_buffer->key_type, protected_str);

    nexus_free(protected_str);

    if (protected_key == NULL) {
        log_error("could not derive key from string\n");
        return NULL;
    }

    // derive raw key and return
    raw_key = nexus_derive_key(raw_key_type, protected_key);

    nexus_free_key(protected_key);
    nexus_free(protected_key);


    return raw_key;
}

struct nexus_key_buffer *
key_buffer_put(struct nexus_key * key, nexus_key_type_t protected_key_type)
{
    struct nexus_key_buffer * key_buffer = NULL;

    struct nexus_key * protected_key = NULL;
    char             * protected_str = NULL;
    size_t             protected_len = 0;

    int ret = -1;


    // derive the key data contents
    {
        ret = -1;

        protected_key = nexus_derive_key(protected_key_type, key);

        if (protected_key == NULL) {
            log_error("could not derive the wrapped or sealed key\n");
            return NULL;
        }

        protected_str = nexus_key_to_str(protected_key);

        if (protected_str == NULL) {
            log_error("could not write key to buffer\n");
            goto out;
        }
    }

    // generate the key buffer data
    {
        key_buffer = nexus_malloc(sizeof(struct nexus_key_buffer));

        key_buffer->key_type = protected_key_type;

        protected_len = strlen(protected_str);

        ret = ocall_calloc((void **) &key_buffer->key_str, protected_len + 1);

        if (ret != 0 || key_buffer->key_str == NULL) {
            log_error("ocall_calloc FAILED (err=%d)\n", ret);
            goto out;
        }

        // copy out the sealed/wrapped key
        strncpy(key_buffer->key_str, protected_str, protected_len);
    }

    ret = 0;
out:
    if (protected_key) {
        nexus_free_key(protected_key);
        nexus_free(protected_key);
    }

    if (protected_str) {
        nexus_free(protected_str);
    }

    if (ret) {
        if (key_buffer) {
            nexus_free(key_buffer);
        }

        return NULL;
    }

    return key_buffer;
}
