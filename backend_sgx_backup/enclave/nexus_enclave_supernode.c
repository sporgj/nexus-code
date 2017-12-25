#include "nexus_trusted.h"

struct supernode *
supernode_copy_whole(struct supernode * supernode)
{
    struct supernode * supernode_copy = NULL;

    size_t size = supernode->header.total_size;


    supernode_copy = (struct supernode *)calloc(1, size);
    
    if (supernode_copy == NULL) {
        ocall_print("allocation error");
        return NULL;
    }

    memcpy(supernode_copy, supernode, size);


    return supernode_copy;
}
