#pragma once

uint8_t *
io_buffer_alloc(size_t size, struct nexus_uuid * uuid, struct nexus_volume * volume);

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_flags_t      flags,
              size_t              * p_size,
              size_t              * timestamp,
              struct nexus_volume * volume);

int
io_buffer_put(struct nexus_uuid   * uuid,
              uint8_t             * heap_ptr,
              size_t                size,
              size_t              * timestamp,
              struct nexus_volume * volume);


