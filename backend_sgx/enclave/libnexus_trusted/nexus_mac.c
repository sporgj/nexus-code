#include <string.h>

#include "nexus_mac.h"
#include "nexus_util.h"

void
nexus_mac_zeroize(struct nexus_mac * mac)
{
    memset(mac, 0, sizeof(struct nexus_mac));
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
    int                ret     = 0;

    new_mac = nexus_malloc(sizeof(struct nexus_mac));

    ret = __nexus_mac_from_buf(new_mac, buf);

    if (ret == -1) {
        nexus_free(new_mac);
        return NULL;
    }

    return new_mac;
}

void
mac_and_version_copy(struct mac_and_version * src_macversion, struct mac_and_version * dst_macversion)
{
    memcpy(dst_macversion, src_macversion, sizeof(struct mac_and_version));
}

void
__mac_and_version_to_buf(struct mac_and_version * macversion, uint8_t * buf)
{
    __mac_and_version_bytes_t * mac_version_bytes = (struct __mac_and_version_bytes *)buf;

    mac_version_bytes->version = macversion->version;
    nexus_mac_to_buf(&macversion->mac, mac_version_bytes->mac_bytes);
}

void
__mac_and_version_from_buf(struct mac_and_version * macversion, uint8_t * buf)
{
    __mac_and_version_bytes_t * mac_version_bytes = (struct __mac_and_version_bytes *)buf;

    macversion->version = mac_version_bytes->version;
    __nexus_mac_from_buf(&macversion->mac, mac_version_bytes->mac_bytes);
}
