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

    if (dirnode_remove(dirnode, filename_IN, &type, uuid_OUT, NULL)) {
        log_error("dirnode_remove() FAILED\n");
        return -1;
    }

    if (type != NEXUS_LNK) {
        nexus_vfs_delete(uuid_OUT);
    }

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


    dentry_delete_child(dentry, filename_IN);


    ret = __nxs_fs_remove(metadata, filename_IN, &entry_uuid);
    if (ret != 0) {
        log_error("__nxs_fs_remove() FAILED\n");
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

    ret = __nxs_fs_lookup(metadata, filename_IN, &entry_uuid);
    if (ret != 0) {
        // lookups fail very often, no need to report the error
        goto out;
    }

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
                 char                  * symlink_target,
                 struct nexus_uuid     * entry_uuid)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;


    nexus_uuid_gen(entry_uuid);

    if (dirnode_add_link(dirnode, link_name, symlink_target, entry_uuid)) {
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

    ret = buffer_layer_hardlink(link_uuid, &target_uuid);

    if (ret != 0) {
        log_error("buffer_layer_hardlink() FAILED\n");
        return -1;
    }

    ret = dirnode_add(link_dirnode, link_name_IN, NEXUS_REG, link_uuid);

    if (ret != 0) {
        // TODO undo the hardlink

        log_error("dirnode_add(%s) FAILED\n", target_name_IN);
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

int
__nxs_fs_rename(struct nexus_dirnode * from_dirnode,
                char                 * oldname,
                struct nexus_dirnode * to_dirnode,
                char                 * newname,
                struct nexus_uuid    * old_uuid,
                struct nexus_uuid    * new_uuid)
{
    int ret = -1;

    nexus_dirent_type_t type;
    nexus_dirent_type_t tmp_type;

    char * symlink_target = NULL;

    ret = dirnode_remove(from_dirnode, oldname, &type, old_uuid, &symlink_target);

    if (ret != 0) {
        log_error("could not remove (%s) from directory\n", oldname);
        return -1;
    }


    // for example if moving foo/bar.txt to cat/, if bar.txt already exists in cat/, we need to remove it
    ret = dirnode_remove(to_dirnode, newname, &tmp_type, new_uuid, NULL);

    if (ret == 0) {
        // this means there was an existing entry in the dirnode
        // TODO remove uuid from vfs_metadata cache
        nexus_vfs_delete(new_uuid);
    } else {
        // we are adding a file to the destination dirnode
        nexus_uuid_gen(new_uuid);
        ret = 0;
    }

    if (type == NEXUS_LNK) {
        ret = dirnode_add_link(to_dirnode, newname, symlink_target, new_uuid);

        nexus_free(symlink_target);
    } else {
        ret = dirnode_add(to_dirnode, newname, type, new_uuid);
    }

    if (ret != 0) {
        log_error("could not add entry to destination directory\n");
        return -1;
    }


    ret = buffer_layer_rename(old_uuid, new_uuid);

    if (ret != 0) {
        log_error("buffer_layer_rename() FAILED\n");
        return -1;
    }

    return 0;
}


int
ecall_fs_rename(char              * from_dirpath_IN,
                char              * oldname_IN,
                char              * to_dirpath_IN,
                char              * newname_IN,
                struct nexus_uuid * old_uuid_out,
                struct nexus_uuid * new_uuid_out)
{
    struct nexus_metadata * from_metadata = NULL;
    struct nexus_metadata * to_metadata   = NULL;
    struct nexus_metadata * tmp_metadata  = NULL;

    struct nexus_dentry * from_dentry = NULL;
    struct nexus_dentry * to_dentry   = NULL;

    struct nexus_uuid old_uuid;
    struct nexus_uuid new_uuid;

    int ret = -1;


    // get the necessary metadata
    from_metadata = nexus_vfs_get(from_dirpath_IN, NEXUS_DIRNODE, &from_dentry);

    if (from_metadata == NULL) {
        log_error("could not get metadata (%s)\n", from_dirpath_IN);
        return -1;
    }

    to_metadata = nexus_vfs_get(to_dirpath_IN, NEXUS_DIRNODE, &to_dentry);

    if (to_metadata == NULL) {
        nexus_vfs_put(from_metadata);

        log_error("could not get metadata (%s)\n", to_dirpath_IN);
        return -1;
    }

    dentry_delete_child(from_dentry, oldname_IN);
    dentry_delete_child(to_dentry, newname_IN);

    // if it's the same dirnode
    if (dirnode_compare(from_metadata->dirnode, to_metadata->dirnode) == 0) {
        nexus_vfs_put(to_metadata);

        to_metadata = NULL;

        tmp_metadata = from_metadata;
    } else {
        tmp_metadata = to_metadata;
    }


    ret = __nxs_fs_rename(from_metadata->dirnode,
                          oldname_IN,
                          tmp_metadata->dirnode,
                          newname_IN,
                          &old_uuid,
                          &new_uuid);

    if (ret != 0) {
        log_error("rename operation failed\n");
        goto out_err;
    }


    ret = nexus_vfs_flush(from_metadata);

    if (ret != 0) {
        log_error("could not flush source dirnode\n");
        goto out_err;
    }

    if (to_metadata != NULL) {
        ret = nexus_vfs_flush(to_metadata);
        if (ret != 0) {
            log_error("could not flush destination dirnode\n");
            goto out_err;
        }
    }

    nexus_uuid_copy(&old_uuid, old_uuid_out);
    nexus_uuid_copy(&new_uuid, new_uuid_out);

    nexus_vfs_put(from_metadata);

    if (to_metadata) {
        nexus_vfs_put(to_metadata);
    }

    return 0;
out_err:
    nexus_vfs_drop(from_metadata);

    if (to_metadata) {
        nexus_vfs_drop(to_metadata);
    }

    return -1;
}
