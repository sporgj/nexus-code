#pragma once



int
stash_manager_init(struct sgx_backend * backend);


void
stash_manager_destroy();



int
stash_manager_store(struct nexus_uuid   * uuid,
                    struct nexus_mac    * mac,
                    uint32_t              version,
                    struct nexus_volume * volume);

int
stash_manager_fetch(struct nexus_uuid   * uuid,
                    struct nexus_mac    * mac,
                    uint32_t            * version,
                    struct nexus_volume * volume);


int
stash_manager_delete(struct nexus_uuid * uuid, struct nexus_volume * volume);
