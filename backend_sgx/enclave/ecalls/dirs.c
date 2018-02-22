#include "../enclave_internal.h"

inline static int
__nxs_fs_create(struct nexus_metadata * metadata,
                char                  * filename_IN,
                nexus_dirent_type_t     type_IN,
                struct nexus_uuid     * uuid_OUT)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;

    int ret = -1;

    ret = dirnode_add(dirnode, filename_IN, type_IN, uuid_OUT);

    if (ret != 0) {
        log_error("dirnode_add() FAILED\n");
        return -1;
    }

    return 0;
}

int
ecall_fs_create(char                * dirpath_IN,
                char                * filename_IN,
                nexus_dirent_type_t   type_IN,
                struct nexus_uuid   * uuid_out)
{
    struct nexus_metadata * metadata = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    // perform the create operation
    ret = __nxs_fs_create(metadata, filename_IN, type_IN, &entry_uuid);
    if (ret != 0) {
        log_error("__nxs_fs_create() FAILED\n");
        goto out;
    }

    ret = nexus_vfs_flush(metadata);
    if (ret != 0) {
        log_error("flushing metadata FAILED\n");
        goto out;
    }

    // copy out the UUID of the new entry
    nexus_uuid_copy(&entry_uuid, uuid_out);

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}

inline static int
__nxs_fs_remove(struct nexus_metadata * metadata, char * filename_IN, struct nexus_uuid * uuid_OUT)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;

    nexus_dirent_type_t type;

    if (dirnode_remove(dirnode, filename_IN, &type, uuid_OUT)) {
        log_error("dirnode_remove() FAILED\n");
        return -1;
    }

    return 0;
}

int
ecall_fs_remove(char * dirpath_IN, char * filename_IN, struct nexus_uuid * uuid_out)
{
    struct nexus_metadata * metadata = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    // perform the create operation
    ret = __nxs_fs_remove(metadata, filename_IN, &entry_uuid);
    if (ret != 0) {
        log_error("__nxs_fs_delete() FAILED\n");
        goto out;
    }

    ret = nexus_vfs_flush(metadata);
    if (ret != 0) {
        log_error("flushing metadata FAILED\n");
        goto out;
    }

    // copy out the UUID of the new entry
    nexus_uuid_copy(&entry_uuid, uuid_out);

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}

inline static int
__nxs_fs_lookup(struct nexus_metadata * metadata, char * filename_IN, struct nexus_uuid * uuid_OUT)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;

    nexus_dirent_type_t type;

    if (dirnode_find_by_name(dirnode, filename_IN, &type, uuid_OUT)) {
        return -1;
    }

    return 0;
}

int
ecall_fs_lookup(char * dirpath_IN, char * filename_IN, struct nexus_uuid * uuid_out)
{
    struct nexus_metadata * metadata = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    // perform the create operation
    ret = __nxs_fs_lookup(metadata, filename_IN, &entry_uuid);
    if (ret != 0) {
        goto out;
    }

    // copy out the UUID of the new entry
    nexus_uuid_copy(&entry_uuid, uuid_out);

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}

inline static int
__nxs_fs_filldir(struct nexus_metadata * metadata,
                 char                  * dirpath_IN,
                 struct nexus_uuid     * uuid,
                 const char           ** name_ptr,
                 size_t                * name_len)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;

    nexus_dirent_type_t type;

    if (dirnode_find_by_uuid(dirnode, uuid, &type, name_ptr, name_len)) {
        return -1;
    }

    return 0;
}

int
ecall_fs_filldir(char * dirpath_IN, struct nexus_uuid * uuid, char ** filename_out)
{
    struct nexus_metadata * metadata = NULL;

    const char * name_ptr = NULL;
    size_t name_len;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    // perform the create operation
    ret = __nxs_fs_filldir(metadata, dirpath_IN, uuid, &name_ptr, &name_len);
    if (ret != 0) {
        goto out;
    }

    // copy out the filename
    {
        char * untrusted_addr = NULL;

        int err = -1;

        ret = -1;

        err = ocall_calloc((void **)&untrusted_addr, name_len);

        if (err || untrusted_addr == NULL) {
            log_error("allocation error \n");
            goto out;
        }

        memcpy(untrusted_addr, name_ptr, name_len);

        *filename_out = untrusted_addr;
    }

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}
