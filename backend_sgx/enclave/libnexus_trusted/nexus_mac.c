#include <string.h>

#include "nexus_mac.h"
#include "nexus_util.h"

void
nexus_mac_zeroize(struct nexus_mac * mac)
{
    memset_s(mac, sizeof(struct nexus_mac), 0, 1);
}

int
nexus_mac_compare(struct nexus_mac * mac1, struct nexus_mac * mac2)
{
    return memcmp(mac1->bytes, mac2->bytes, NEXUS_MAC_SIZE);
}

void
nexus_mac_copy(struct nexus_mac * src_mac, struct nexus_mac * dst_mac)
{
    memcpy(dst_mac->bytes, src_mac->bytes, NEXUS_MAC_SIZE);

    return;
}

int
nexus_mac_to_buf(struct nexus_mac * mac, uint8_t * buf)
{
    memcpy(buf, mac->bytes, NEXUS_MAC_SIZE);

    return 0;
}

int
__nexus_mac_from_buf(struct nexus_mac * mac, uint8_t * buf)
{
    memcpy(mac->bytes, buf, NEXUS_MAC_SIZE);

    return 0;
}

struct nexus_mac *
nexus_mac_from_buf(uint8_t * buf)
{
    struct nexus_mac * new_mac = NULL;
    int ret = 0;

    new_mac = nexus_malloc(sizeof(struct nexus_mac));

    ret = __nexus_mac_from_buf(new_mac, buf);


    if (ret == -1) {
	nexus_free(new_mac);
	return NULL;
    }

    return new_mac;
}
