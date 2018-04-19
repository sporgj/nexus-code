#pragma once

uint8_t *
io_buffer_alloc(size_t size, struct nexus_uuid * uuid, struct nexus_volume * volume);

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_mode_t       mode,
              size_t              * p_size,
              size_t              * timestamp,
              struct nexus_volume * volume);

int
io_buffer_put(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume);


