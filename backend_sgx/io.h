#pragma once

struct sgx_backend;


uint8_t *
io_buffer_alloc(struct nexus_uuid * uuid, size_t size, struct nexus_volume * volume);

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_flags_t      flags,
              size_t              * p_size,
              size_t              * timestamp,
              struct nexus_volume * volume);

int
io_buffer_put(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume);

int
io_buffer_put_buffer(struct nexus_uuid   * uuid,
                     uint8_t             * buffer,
                     size_t                size,
                     size_t              * timestamp,
                     struct nexus_volume * volume);

struct metadata_buf *
io_buffer_lock(struct nexus_uuid * uuid, struct nexus_volume * volume);


int
io_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume);

int
io_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume);

int
io_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume);

int
io_buffer_hardlink(struct nexus_uuid   * link_uuid,
                   struct nexus_uuid   * target_uuid,
                   struct nexus_volume * volume);

int
io_buffer_rename(struct nexus_uuid   * from_uuid,
                 struct nexus_uuid   * to_uuid,
                 struct nexus_volume * volume);


int
io_manager_flush_dirty(struct sgx_backend * sgx_backend);
