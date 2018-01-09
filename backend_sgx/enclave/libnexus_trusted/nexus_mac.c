#include <string.h>

#include "nexus_mac.h"

int
nexus_mac_equals(struct nexus_mac * mac1, struct nexus_mac * mac2)
{
    return (memcmp(mac1, mac2, sizeof(struct nexus_mac)) == 0);
}

void
nexus_mac_copy(struct nexus_mac * src_mac, struct nexus_mac * dst_mac)
{
    memcpy(dst_mac, src_mac, sizeof(struct nexus_mac));
}
