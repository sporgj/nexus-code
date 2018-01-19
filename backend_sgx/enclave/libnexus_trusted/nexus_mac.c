#include <string.h>

#include "nexus_mac.h"

int
nexus_mac_compare(struct nexus_mac * mac1,
		  struct nexus_mac * mac2)
{
    return memcmp(mac1->bytes, mac2->bytes, NEXUS_MAC_SIZE);
}

void
nexus_mac_copy(struct nexus_mac * src_mac,
	       struct nexus_mac * dst_mac)
{
    memcpy(dst_mac->bytes, src_mac->bytes, NEXUS_MAC_SIZE);

    return;
}
