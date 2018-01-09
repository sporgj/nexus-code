#pragma once

#define CONFIG_MAC_SIZE 16

struct nexus_mac {
    uint8_t bytes[CONFIG_MAC_SIZE];
};


/**
 * returns 1 if mac1 == mac2
 */
int
nexus_mac_equals(struct nexus_mac * mac1, struct nexus_mac * mac2);

void
nexus_mac_copy(struct nexus_mac * src_mac, struct nexus_mac * dst_mac);
