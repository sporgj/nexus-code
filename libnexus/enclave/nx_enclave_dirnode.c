#include "nx_trusted.h"

/**
 * Creates a new dirnode
 */
struct dirnode *
dirnode_new(struct uuid * uuid, struct uuid * root_uuid)
{
    // 1 - allocate a new dirnode
    struct dirnode * dirnode = NULL;
    
    dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    if (dirnode == NULL) {
        ocall_debug("allocation error");
        return NULL;
    }

    // 2 - copy the uuid & root uuid into the dirnode
    memcpy(&dirnode->header.uuid, uuid, sizeof(struct uuid));
    memcpy(&dirnode->header.root_uuid, root_uuid, sizeof(struct uuid));
    dirnode->header.total_size = sizeof(struct dirnode);

    return dirnode;
}

int
dirnode_add(struct dirnode *    dirnode_ext,
            const char *        fname_str,
            size_t              fname_len,
            nexus_fs_obj_type_t type,
            struct uuid *       entry_uuid)
{
    // 1 - checks if the entry is in the dirnode
    // 2 - allocate space for the new dirnode entry
    //
    return 0;
}

int
ecall_dirnode_new(struct uuid *    uuid_ext,
                  struct dirnode * parent_dirnode_ext,
                  struct dirnode * dirnode_out_ext)
{
    int              ret     = -1;
    struct dirnode * dirnode = NULL;
    struct dirnode * sealed_dirnode = NULL;
    struct uuid      uuid;
    struct uuid      root_uuid;

    memcpy(&uuid, uuid_ext, sizeof(struct uuid));
    memcpy(
        &root_uuid, &parent_dirnode_ext->header.root_uuid, sizeof(struct uuid));

    // create the new dirnode and send to the exterior
    dirnode = dirnode_new(&uuid, &root_uuid);
    if (dirnode == NULL) {
        return -1;
    }

    ret = dirnode_encryption(dirnode, &sealed_dirnode);
    if (ret != 0) {
        ocall_debug("dirnode_encrypt_and_seal2() FAILED");
        goto out;
    }

    memcpy(dirnode_out_ext, sealed_dirnode, dirnode->header.total_size);

    ret = 0;
out:
    my_free(dirnode);
    my_free(sealed_dirnode);

    return ret;
}

int
ecall_dirnode_add(struct dirnode *    dirnode_ext,
                  struct uuid *       entry_uuid,
                  const char *        fname_str_in,
                  size_t              fname_str_len,
                  nexus_fs_obj_type_t type)
{
    return 0;
}
