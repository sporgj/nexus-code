#pragma once

#include <stdint.h>

#define CONFIG_MAC_SIZE 16

struct nexus_mac {
    uint8_t bytes[CONFIG_MAC_SIZE];
};


/**
 * Compares two macs
 * @param mac1
 * @param mac2
 *
 * return 0 if equal
 */
int
nexus_mac_compare(struct nexus_mac * mac1, struct nexus_mac * mac2);

void
nexus_mac_copy(struct nexus_mac * src_mac, struct nexus_mac * dst_mac);
