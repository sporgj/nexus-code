#include "../enclave_internal.h"

inline static int
__nxs_fs_create(struct nexus_dirnode  * parent_dirnode,
                char                  * filename_IN,
                nexus_dirent_type_t     type_IN,
                struct nexus_uuid     * entry_uuid)
{
    int ret = -1;


    // create the new metadata
    nexus_uuid_gen(entry_uuid);

    ret = buffer_layer_new(entry_uuid);

    if (ret != 0) {
        log_error("could not create empty metadata \n");
        return -1;
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

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    // perform the create operation
    ret = __nxs_fs_create(metadata->dirnode, filename_IN, type_IN, &entry_uuid);
    if (ret != 0) {
        log_error("__nxs_fs_create() FAILED\n");
        goto out;
    }

    ret = nexus_metadata_store(metadata);
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

    struct nexus_uuid   tmp_uuid;

    nexus_dirent_type_t type;

    if (dirnode_remove(dirnode, filename_IN, &type, uuid_OUT, &tmp_uuid, NULL)) {
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

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FRDWR | NEXUS_FDELETE);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }


    dentry_delete_child(metadata->dentry, filename_IN);

    ret = __nxs_fs_remove(metadata, filename_IN, &entry_uuid);

    if (ret != 0) {
        log_error("__nxs_fs_remove() FAILED\n");
        goto out;
    }

    ret = nexus_metadata_store(metadata);
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

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

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
                 struct nexus_uuid     * uuid,
                 const char           ** name_ptr,
                 size_t                * name_len)
{
    nexus_dirent_type_t type;

    if (dirnode_find_by_uuid(metadata->dirnode, uuid, &type, name_ptr, name_len)) {
        return -1;
    }

    return 0;
}


int
__nxs_fs_stat(struct nexus_dirnode * dirnode, char * plain_name, struct nexus_stat * stat_info)
{
    struct nexus_uuid real_uuid;
    struct nexus_uuid link_uuid;

    nexus_dirent_type_t dirent_type;
    nexus_metadata_type_t metadata_type;


    if (__dirnode_find_by_name(dirnode, plain_name, &dirent_type, &link_uuid, &real_uuid)) {
        return -1;
    }

    if (dirent_type == NEXUS_LNK) {
        stat_info->size = 0;
        stat_info->type = NEXUS_LNK;
        return 0;
    }

    metadata_type = (dirent_type == NEXUS_REG ? NEXUS_FILENODE : NEXUS_DIRNODE);

    // load the metadata and read its contents
    {
        struct nexus_metadata * metadata = nexus_vfs_load(&link_uuid, metadata_type, NEXUS_FREAD);

        if (metadata == NULL) {
            return -1;
        }

        if (metadata_type == NEXUS_DIRNODE) {
            struct nexus_dirnode * dirnode = metadata->dirnode;

            stat_info->size = dirnode->dir_entry_count;
            stat_info->type = NEXUS_DIR;
        } else {
            struct nexus_filenode * filenode = metadata->filenode;

            stat_info->size = filenode->filesize;
            stat_info->type = NEXUS_REG;
        }

        nexus_vfs_put(metadata);
    }

    nexus_uuid_copy(&link_uuid, &stat_info->uuid);

    return 0;
}

int
ecall_fs_stat(char * dirpath_IN, char * plain_name_IN, struct nexus_stat * nexus_stat_out)
{
    struct nexus_metadata * metadata = NULL;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    if (metadata->type != NEXUS_DIRNODE) {
        nexus_vfs_put(metadata);

        log_error("the path is not a directory\n");
        return -1;
    }

    ret = __nxs_fs_stat(metadata->dirnode, plain_name_IN, nexus_stat_out);

    if (ret != 0) {
        goto out;
    }

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;

}

int
ecall_fs_filldir(char * dirpath_IN, struct nexus_uuid * uuid, char filename_out[NEXUS_NAME_MAX])
{
    struct nexus_metadata * metadata = NULL;

    const char * name_ptr = NULL;
    size_t name_len;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    ret = __nxs_fs_filldir(metadata, uuid, &name_ptr, &name_len);
    if (ret != 0) {
        goto out;
    }

    // copy out the filename
    strncpy(filename_out, name_ptr, NEXUS_NAME_MAX);

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}

int
ecall_fs_readdir(char                * dirpath_IN,
                 struct nexus_dirent * dirent_buffer_array_out,
                 size_t                dirent_buffer_count_IN,
                 size_t                offset_IN,
                 size_t              * result_count_out,
                 size_t              * directory_size_out)
{
    struct nexus_metadata * metadata = NULL;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    ret = UNSAFE_dirnode_readdir(metadata->dirnode,
                                 dirent_buffer_array_out,
                                 dirent_buffer_count_IN,
                                 offset_IN,
                                 result_count_out,
                                 directory_size_out);

    if (ret != 0) {
        log_error("could not readdir the directory\n");
        goto out;
    }

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}


int
__nxs_fs_symlink(struct nexus_metadata * metadata,
                 char                  * link_name,
                 char                  * symlink_target,
                 struct nexus_uuid     * entry_uuid)
{
    nexus_uuid_gen(entry_uuid);

    if (dirnode_add_link(metadata->dirnode, link_name, symlink_target, entry_uuid)) {
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

    struct nexus_uuid entry_uuid;

    int ret = -1;


    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }


    ret = __nxs_fs_symlink(metadata, linkname_IN, targetpath_IN, &entry_uuid);

    if (ret != 0) {
        log_error("symlink operation failed\n");
        goto out;
    }


    ret = nexus_metadata_store(metadata);

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
__nxs_fs_hardlink(struct nexus_dirnode * src_dirnode,
                  char                 * src_name_IN,
                  struct nexus_dirnode * dst_dirnode,
                  char                 * dst_name_IN,
                  struct nexus_uuid    * dst_uuid)
{
    nexus_dirent_type_t src_type;

    struct nexus_uuid   src_uuid;

    int ret = -1;


    ret = dirnode_find_by_name(src_dirnode, src_name_IN, &src_type, &src_uuid);

    if (ret != 0) {
        log_error("dirnode_find_by_name(%s) FAILED\n", src_name_IN);
        return -1;
    }

    if (src_type != NEXUS_REG) {
        log_error("NEXUS only supports hardlinking files\n");
        return -1;
    }

    // generate the uuid and add entry to dirnode
    nexus_uuid_gen(dst_uuid);

    ret = buffer_layer_hardlink(dst_uuid, &src_uuid);

    if (ret != 0) {
        log_error("buffer_layer_hardlink() FAILED\n");
        return -1;
    }

    ret = dirnode_add(dst_dirnode, dst_name_IN, NEXUS_REG, dst_uuid);

    if (ret != 0) {
        // TODO undo the hardlink

        log_error("dirnode_add(%s) FAILED\n", dst_name_IN);
        return -1;
    }

    return 0;
}

int
ecall_fs_hardlink(char              * src_dirpath_IN,
                  char              * src_name_IN,
                  char              * dst_dirpath_IN,
                  char              * dst_name_IN,
                  struct nexus_uuid * entry_uuid_out)
{
    struct nexus_metadata * dst_metadata = NULL;
    struct nexus_metadata * src_metadata = NULL;

    struct nexus_uuid       dst_uuid;

    int                     ret          = -1;


    dst_metadata = nexus_vfs_get(dst_dirpath_IN, NEXUS_FRDWR);

    if (dst_metadata == NULL) {
        log_error("could not get metadata\n");
        return -1;
    }

    if (strncmp(dst_dirpath_IN, src_dirpath_IN, NEXUS_PATH_MAX) == 0) {
        src_metadata = nexus_metadata_get(dst_metadata);
        goto do_hardlink;
    }

    src_metadata = nexus_vfs_get(src_dirpath_IN, NEXUS_FREAD);

    if (src_metadata == NULL) {
        nexus_vfs_put(dst_metadata);
        log_error("could not get metadata\n");
        return -1;
    }

do_hardlink:
    ret = __nxs_fs_hardlink(src_metadata->dirnode,
                            src_name_IN,
                            dst_metadata->dirnode,
                            dst_name_IN,
                            &dst_uuid);

    if (ret != 0) {
        log_error("__nxs_fs_hardlink() FAILED\n");
        goto out;
    }

    ret = nexus_metadata_store(dst_metadata);

    if (ret != 0) {
        log_error("flushing metadata FAILED\n");
        goto out;
    }

    // copy out the UUID of the new entry
    nexus_uuid_copy(&dst_uuid, entry_uuid_out);

    ret = 0;
out:
    nexus_vfs_put(src_metadata);
    nexus_vfs_put(dst_metadata);

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
    nexus_dirent_type_t type;
    nexus_dirent_type_t tmp_type;

    struct nexus_uuid   real_uuid;
    struct nexus_uuid   tmp_uuid;

    char * symlink_target = NULL;

    int ret = -1;


    ret = dirnode_remove(from_dirnode, oldname, &type, old_uuid, &real_uuid, &symlink_target);

    if (ret != 0) {
        log_error("could not remove (%s) from directory\n", oldname);
        return -1;
    }


    // for example if moving foo/bar.txt to cat/, if bar.txt already exists in cat/, we need to remove it
    ret = dirnode_remove(to_dirnode, newname, &tmp_type, new_uuid, &tmp_uuid, NULL);

    if (ret == 0) {
        // this means there was an existing entry in the dirnode
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
        ret = dirnode_add2(to_dirnode, newname, type, new_uuid, &real_uuid);
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

    struct nexus_dentry   * from_dentry   = NULL;
    struct nexus_dentry   * to_dentry     = NULL;

    struct nexus_uuid old_uuid;
    struct nexus_uuid new_uuid;

    int ret = -1;


    // if it's the same directory, just skip to editing the same dirnode
    if (strncmp(from_dirpath_IN, to_dirpath_IN, NEXUS_PATH_MAX) == 0) {
        from_metadata = nexus_vfs_get(from_dirpath_IN, NEXUS_FRDWR);
        tmp_metadata  = from_metadata;

        goto do_rename;
    }

    // get the necessary metadata
    from_dentry = nexus_vfs_lookup(from_dirpath_IN);
    to_dentry   = nexus_vfs_lookup(to_dirpath_IN);

    if (from_dentry == NULL || to_dentry == NULL) {
        log_error("could not find dentry\n");
        return -1;
    }


    // if they are the same dentry...
    if (from_dentry == to_dentry) {
        from_metadata = dentry_get_metadata(from_dentry, NEXUS_FRDWR, true);
        tmp_metadata  = from_metadata;

        goto do_rename;
    }

    from_metadata = dentry_get_metadata(from_dentry, NEXUS_FRDWR, true);
    to_metadata   = dentry_get_metadata(to_dentry, NEXUS_FRDWR, true);
    tmp_metadata  = to_metadata;

do_rename:
    if (from_metadata == NULL) {
        log_error("could not get source metadata\n");
        return -1;
    }

    if (tmp_metadata == NULL) {
        nexus_vfs_put(from_metadata);

        log_error("could not get destination metadata\n");
        return -1;
    }


    dentry_delete_child(from_metadata->dentry, oldname_IN);
    dentry_delete_child(tmp_metadata->dentry, newname_IN);

    ret = __nxs_fs_rename(from_metadata->dirnode,
                          oldname_IN,
                          tmp_metadata->dirnode,
                          newname_IN,
                          &old_uuid,
                          &new_uuid);

    if (ret != 0) {
        log_error("rename operation failed\n");
        goto out;
    }


    ret = nexus_metadata_store(from_metadata);

    if (ret != 0) {
        log_error("could not flush source dirnode\n");
        goto out;
    }

    if (to_metadata != NULL) {
        ret = nexus_metadata_store(to_metadata);

        if (ret != 0) {
            log_error("could not flush destination dirnode\n");
            goto out;
        }
    }

    nexus_uuid_copy(&old_uuid, old_uuid_out);
    nexus_uuid_copy(&new_uuid, new_uuid_out);

    ret = 0;

out:
    nexus_vfs_put(from_metadata);

    if (to_metadata) {
        nexus_vfs_put(to_metadata);
    }

    return ret;
}
