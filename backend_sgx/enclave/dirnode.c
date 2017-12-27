#include "internal.h"

struct dirnode *
dirnode_create(struct nexus_uuid * root_uuid)
{
    struct dirnode * dirnode = NULL;

    dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    if (dirnode == NULL) {
        ocall_debug("allocation error");
        return NULL;
    }

    sgx_read_rand((uint8_t *)&dirnode->my_uuid, sizeof(struct nexus_uuid));
    memcpy(&dirnode->root_uuid, root_uuid, sizeof(struct nexus_uuid));


    return dirnode;
}

int
dirnode_store(struct dirnode * dirnode)
{
    // TODO
    return -1;
}

void
dirnode_free(struct dirnode * dirnode)
{
    // TODO
}
