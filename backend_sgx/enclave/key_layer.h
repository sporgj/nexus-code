#pragma once

#include <nexus_key.h>

void
key_buffer_copy(struct nexus_key_buffer * src_buffer, struct nexus_key_buffer * dst_buffer);

void
key_buffer_free(struct nexus_key_buffer * key_buffer);

struct nexus_key *
key_buffer_get(struct nexus_key_buffer * key_buffer, nexus_key_type_t key_type);

struct nexus_key_buffer *
key_buffer_put(struct nexus_key * key, nexus_key_type_t key_type);


