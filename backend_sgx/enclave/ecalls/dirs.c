#include "../enclave_internal.h"

inline static int
__nxs_fs_create(struct nexus_dirnode  * parent_dirnode,
                struct nexus_dentry   * dentry,
                char                  * filename_IN,
                nexus_dirent_type_t     type_IN,
                struct nexus_uuid     * entry_uuid)
{
    nexus_metadata_type_t metadata_type = (type_IN == NEXUS_DIR) ? NEXUS_DIRNODE : NEXUS_FILENODE;

    int ret = -1;

    // create the new metadata
    {
        struct nexus_metadata * new_metadata = NULL;

        new_metadata = nexus_vfs_create(dentry, metadata_type);

        if (new_metadata == NULL) {
            log_error("could not create metadata\n");
            return -1;
        }

        ret = nexus_vfs_flush(new_metadata);

        if (ret != 0) {
            nexus_vfs_put(new_metadata);
            log_error("could not flush metadata\n");
            return -1;
        }

        nexus_uuid_copy(&new_metadata->uuid, entry_uuid);

        nexus_vfs_put(new_metadata);
    }

    // update the parent dirnode
    ret = dirnode_add(parent_dirnode, filename_IN, type_IN, entry_uuid);

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

    struct nexus_dentry * dentry = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE, &dentry);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    // perform the create operation
    ret = __nxs_fs_create(metadata->dirnode, dentry, filename_IN, type_IN, &entry_uuid);
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

    nexus_vfs_delete(uuid_OUT);

    return 0;
}

int
ecall_fs_remove(char * dirpath_IN, char * filename_IN, struct nexus_uuid * uuid_out)
{
    struct nexus_metadata * metadata = NULL;

    struct nexus_dentry * dentry = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE, &dentry);

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

    struct nexus_dentry * dentry = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE, &dentry);

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

    struct nexus_dentry * dentry = NULL;

    const char * name_ptr = NULL;
    size_t name_len;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE, &dentry);

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

int
__nxs_fs_symlink(struct nexus_metadata * metadata,
                 char                  * dirpath_IN,
                 char                  * link_name,
                 char                  * target_path,
                 struct nexus_uuid     * entry_uuid)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;


    nexus_uuid_gen(entry_uuid);

    if (dirnode_add_link(dirnode, link_name, target_path, entry_uuid)) {
        log_error("could not add link to dirnode\n");
        return -1;
    }

    return 0;
}

int
ecall_fs_symlink(char              * dirpath_IN,
                 char              * linkname_IN,
                 char              * targetpath_IN,
                 struct nexus_uuid * uuid_out)
{
    struct nexus_metadata * metadata = NULL;

    struct nexus_dentry * dentry = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_DIRNODE, &dentry);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }


    ret = __nxs_fs_symlink(metadata, dirpath_IN, linkname_IN, targetpath_IN, &entry_uuid);

    if (ret != 0) {
        log_error("symlink operation failed\n");
        goto out;
    }


    ret = nexus_vfs_flush(metadata);

    if (ret != 0) {
        log_error("flushing metadata FAILED\n");
        goto out;
    }


    nexus_uuid_copy(&entry_uuid, uuid_out);

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}

int
__nxs_fs_hardlink(struct nexus_dirnode * link_dirnode,
                  char                 * link_name_IN,
                  struct nexus_dirnode * target_dirnode,
                  char                 * target_name_IN,
                  struct nexus_uuid    * link_uuid)
{
    nexus_dirent_type_t target_type;

    struct nexus_uuid target_uuid;

    int ret = -1;


    ret = dirnode_find_by_name(target_dirnode, target_name_IN, &target_type, &target_uuid);

    if (ret != 0) {
        log_error("dirnode_find_by_name(%s) FAILED\n", target_name_IN);
        return -1;
    }

    if (target_type != NEXUS_REG) {
        log_error("NEXUS only supports hardlinking files\n");
        return -1;
    }

    // generate the uuid and add entry to dirnode
    nexus_uuid_gen(link_uuid);

    ret = buffer_layer_hardlink(&target_uuid, link_uuid);

    if (ret != 0) {
        log_error("buffer_layer_hardlink() FAILED\n");
        return -1;
    }

    ret = dirnode_add(link_dirnode, link_name_IN, NEXUS_REG, link_uuid);

    if (ret != 0) {
        // TODO undo the hardlink

        log_error("dirnode_find_by_name(%s) FAILED\n", target_name_IN);
        return -1;
    }

    return 0;
}

int
ecall_fs_hardlink(char              * link_dirpath_IN,
                  char              * link_name_IN,
                  char              * target_dirpath_IN,
                  char              * target_name_IN,
                  struct nexus_uuid * entry_uuid_out)
{
    struct nexus_metadata * link_metadata   = NULL;
    struct nexus_metadata * target_metadata = NULL;

    struct nexus_dentry * link_dentry   = NULL;
    struct nexus_dentry * target_dentry = NULL;

    struct nexus_uuid link_uuid;

    int ret = -1;


    (void)link_dentry;
    (void)target_dentry;


    link_metadata = nexus_vfs_get(link_dirpath_IN, NEXUS_DIRNODE, &link_dentry);

    if (link_metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    target_metadata = nexus_vfs_get(target_dirpath_IN, NEXUS_DIRNODE, &target_dentry);

    if (target_metadata == NULL) {
        nexus_vfs_put(link_metadata);
        log_error("could not get metadata\n");
        return -1;
    }

    ret = __nxs_fs_hardlink(link_metadata->dirnode,
                            link_name_IN,
                            target_metadata->dirnode,
                            target_name_IN,
                            &link_uuid);

    if (ret != 0) {
        log_error("__nxs_fs_hardlink() FAILED\n");
        goto out;
    }

    ret = nexus_vfs_flush(link_metadata);
    if (ret != 0) {
        log_error("flushing metadata FAILED\n");
        goto out;
    }

    // copy out the UUID of the new entry
    nexus_uuid_copy(&link_uuid, entry_uuid_out);

    ret = 0;
out:
    nexus_vfs_put(link_metadata);
    nexus_vfs_put(target_metadata);

    return ret;
}
