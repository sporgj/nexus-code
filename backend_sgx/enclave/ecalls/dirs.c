#include "../enclave_internal.h"

inline static int
__nxs_fs_create(char                * dirpath_IN,
                char                * filename_IN,
                nexus_dirent_type_t   type_IN,
                struct nexus_uuid   * uuid_out)
{
    struct nexus_dirnode * dirnode = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    dirnode = nexus_vfs_find_dirnode(dirpath_IN);
    if (dirnode == NULL) {
        log_error("nexus_vfs_find_dirnode() FAILED\n");
        return -1;
    }

    ret = dirnode_add(dirnode, filename_IN, type_IN, &entry_uuid);
    if (ret != 0) {
        nexus_vfs_put_dirnode(dirnode);
        log_error("dirnode_add() FAILED\n");
        return -1;
    }

    nexus_uuid_copy(&entry_uuid, uuid_out);

    return ret;
}

int
ecall_fs_create(char                * dirpath_IN,
                char                * filename_IN,
                nexus_dirent_type_t   type_IN,
                struct nexus_uuid   * uuid_OUT)
{
    return __nxs_fs_create(dirpath_IN, filename_IN, type_IN, uuid_OUT);
}
