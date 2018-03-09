#pragma once

void
key_buffer_init(struct nexus_key_buffer * key_buffer);

int
key_buffer_put(struct nexus_key_buffer * key_buffer, struct nexus_key * key);

void
key_buffer_free(struct nexus_key_buffer * key_buffer);

int
key_buffer_derive(struct nexus_key_buffer * key_buffer, struct nexus_key * key);
