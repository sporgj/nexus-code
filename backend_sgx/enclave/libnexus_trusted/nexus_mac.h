#pragma once

#include <stdint.h>

#define NEXUS_MAC_SIZE 16

struct nexus_mac {
    uint8_t bytes[NEXUS_MAC_SIZE];
};


void
nexus_mac_zeroize(struct nexus_mac * mac);

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


int
nexus_mac_to_buf(struct nexus_mac * mac, uint8_t * buf);

struct nexus_mac *
nexus_mac_from_buf(uint8_t * buf);

int
__nexus_mac_from_buf(struct nexus_mac * mac, uint8_t * buf);
