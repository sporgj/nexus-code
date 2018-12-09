#pragma once

#include <nexus_volume.h>
#include <nexus_mac.h>


struct sgx_backend;


int
hashtree_manager_init(struct sgx_backend * backend);


void
hashtree_manager_destroy(struct sgx_backend * backend);


int
hashtree_manager_update(uint32_t version, struct nexus_mac * mac, struct nexus_volume * volume);


int
hashtree_manager_fetch(uint32_t * version, struct nexus_mac * mac, struct nexus_volume * volume);
