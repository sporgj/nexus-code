#include "../enclave_internal.h"


inline static int
__nxs_fs_create(struct nexus_dirnode  * parent_dirnode,
                char                  * filename_IN,
                nexus_dirent_type_t     type_IN,
                struct nexus_uuid     * entry_uuid)
{
    nexus_uuid_gen(entry_uuid);

    if (buffer_layer_new(entry_uuid)) {
        log_error("buffer_layer_new() FAILED\n");
        return -1;
    }

    // update the parent dirnode
    if (dirnode_add(parent_dirnode, filename_IN, type_IN, entry_uuid)) {
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


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    nexus_abac_access_check(metadata, PERM_WRITE);

    if (!bouncer_access_check(metadata, PERM_WRITE)) {
        log_error("you are not allowed\n");
        goto out;
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
    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}

static int
__remove_filenode(struct nexus_uuid * uuid, bool * should_remove)
{
    struct hardlink_table * hardlink_table = nexus_vfs_acquire_hardlink_table(NEXUS_FRDWR);

    if (hardlink_table == NULL) {
        log_error("nexus_vfs_acquire_hardlink_table() FAILED\n");
        return -1;
    }

    if (!hardlink_table_contains_uuid(hardlink_table, uuid)) {
        nexus_vfs_release_hardlink_table();
        nexus_vfs_delete(uuid);
        *should_remove = true;
        return 0;
    }

    if (hardlink_table_decr_uuid(hardlink_table, uuid) == 0) {
        *should_remove = true;
        nexus_vfs_delete(uuid);
        return nexus_vfs_flush_hardlink_table();
    }

    *should_remove = false;

    return nexus_vfs_flush_hardlink_table();
}

inline static int
__remove_dirnode(struct nexus_uuid * uuid, bool check_emptiness)
{
    // TODO if not empty, add this dirnode to the garbage list
    nexus_vfs_delete(uuid);
    return 0;
}

inline static int
__nxs_fs_remove(struct nexus_metadata  * metadata,
                char                   * filename_IN,
                struct nexus_fs_lookup * fs_lookup_OUT,
                bool                   * should_remove)
{
    struct nexus_dirnode * dirnode = metadata->dirnode;

    struct nexus_uuid   * tmp_uuid = NULL;

    nexus_dirent_type_t   tmp_type;


    struct dir_entry * direntry = __dirnode_search_and_check(dirnode, filename_IN, NEXUS_FDELETE);

    if (direntry == NULL) {
        return -1;
    }

    tmp_uuid = &direntry->dir_rec.link_uuid;
    tmp_type = direntry->dir_rec.type;

    *should_remove = true;

    if (tmp_type == NEXUS_REG) {
        if (__remove_filenode(tmp_uuid, should_remove)) {
            return -1;
        }
    } else if (tmp_type == NEXUS_DIR) {
        __remove_dirnode(tmp_uuid, true);
    }

    nexus_uuid_copy(tmp_uuid, &fs_lookup_OUT->uuid);
    fs_lookup_OUT->type = tmp_type;

    __dirnode_clobber_dir_entry(dirnode, direntry);

    return 0;
}

int
ecall_fs_remove(char                   * dirpath_IN,
                char                   * filename_IN,
                struct nexus_fs_lookup * fs_lookup_OUT,
                bool                   * should_remove_out)
{
    struct nexus_metadata * metadata = NULL;

    bool should_remove = true; // TODO make this ecall argument

    int ret = -1;


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }


    dentry_delete_child(metadata_get_dentry(metadata), filename_IN);

    ret = __nxs_fs_remove(metadata, filename_IN, fs_lookup_OUT, &should_remove);

    if (ret != 0) {
        log_error("__nxs_fs_remove() FAILED\n");
        goto out;
    }

    ret = nexus_metadata_store(metadata);
    if (ret != 0) {
        log_error("flushing metadata FAILED\n");
        goto out;
    }

    *should_remove_out = should_remove;

    ret = 0;
out:
    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}

inline static int
__nxs_fs_lookup(struct nexus_dirnode   * dirnode,
                char                   * filename_IN,
                struct nexus_fs_lookup * lookup_info)
{
    struct nexus_uuid   uuid;
    nexus_dirent_type_t type;

    if (dirnode_find_by_name(dirnode, filename_IN, &type, &uuid)) {
        return -1;
    }

    lookup_info->type = type;
    nexus_uuid_copy(&uuid, &lookup_info->uuid);

    return 0;
}

int
ecall_fs_lookup(char * dirpath_IN, char * filename_IN, struct nexus_fs_lookup * lookup_out)
{
    struct nexus_metadata * metadata = NULL;

    struct nexus_uuid entry_uuid;

    int ret = -1;


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    ret = __nxs_fs_lookup(metadata->dirnode, filename_IN, lookup_out);

    if (ret != 0) {
        // lookups fail very often, no need to report the error
        goto out;
    }

    ret = 0;
out:
    nexus_vfs_put(metadata);

    sgx_spin_unlock(&vfs_ops_lock);
    return ret;
}


static int
__export_link_count(struct nexus_uuid * uuid, struct nexus_stat * stat_out)
{
    struct hardlink_table * hardlink_table = nexus_vfs_acquire_hardlink_table(NEXUS_FREAD);

    if (hardlink_table == NULL) {
        log_error("WARN: nexus_vfs_acquire_hardlink_table() FAILED\n");
        return -1;
    }

    if (hardlink_table_contains_uuid(hardlink_table, uuid)) {
        hardlink_table_get_uuid(hardlink_table, uuid, &stat_out->link_count);
    } else {
        stat_out->link_count = 0;
    }

    nexus_vfs_release_hardlink_table();

    return 0;
}

int
ecall_fs_stat(char * path_IN, nexus_stat_flags_t stat_flags, struct nexus_stat * nexus_stat_out)
{
    struct path_walker      walker        = { 0 };

    struct nexus_dentry   * parent_dentry = NULL;

    int ret = 0;


    sgx_spin_lock(&vfs_ops_lock);

    parent_dentry = nexus_vfs_lookup_parent(path_IN, &walker);

    if (parent_dentry == NULL) {
        sgx_spin_unlock(&vfs_ops_lock);
        log_error("could not get parent dentry\n");
        return -1;
    }

    if (stat_flags & NEXUS_STAT_LINK) {
        struct nexus_dirnode * dirnode = parent_dentry->metadata->dirnode;

        ret = 0;

        if (walker.remaining_path) {
            ret = dirnode_export_link_stat(dirnode, walker.remaining_path, nexus_stat_out);

            if (ret == 0 && nexus_stat_out->link_type == NEXUS_REG) {
                __export_link_count(&dirnode->my_uuid, nexus_stat_out);
            }
        } else {
            // it is the root directory
            dirnode_export_stat(dirnode, nexus_stat_out);
        }
    }

    if (stat_flags & NEXUS_STAT_FILE || nexus_stat_out->link_type != NEXUS_LNK) {
        struct nexus_metadata * metadata = nexus_vfs_complete_lookup(&walker, NEXUS_FREAD);

        if (metadata == NULL) {
            log_error("could not get metadata\n");
            sgx_spin_unlock(&vfs_ops_lock);

            return -1;
        }

        if (metadata->type == NEXUS_DIRNODE) {
            dirnode_export_stat(metadata->dirnode, nexus_stat_out);
        } else {
            filenode_export_stat(metadata->filenode, nexus_stat_out);

            __export_link_count(&metadata->uuid, nexus_stat_out);
        }

        nexus_vfs_put(metadata);
    }

    sgx_spin_unlock(&vfs_ops_lock);

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


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
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
    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}


int
__nxs_fs_symlink(struct nexus_metadata * metadata,
                 char                  * link_name,
                 char                  * symlink_target,
                 struct nexus_uuid     * entry_uuid)
{
    nexus_uuid_gen(entry_uuid);

    if (buffer_layer_new(entry_uuid)) {
        log_error("could not create empty metadata \n");
        return -1;
    }

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


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
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
    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}

static char *
__nxs_fs_readlink(struct nexus_dirnode * dirnode, char * link_name)
{
    nexus_dirent_type_t type;

    struct nexus_uuid uuid;

    if (dirnode_find_by_name(dirnode, link_name, &type, &uuid)) {
        return NULL;
    }

    return dirnode_get_link(dirnode, &uuid);
}

int
ecall_fs_readlink(char * dirpath_IN, char * linkname_IN, char targetpath_out[NEXUS_PATH_MAX])
{
    struct nexus_metadata * metadata = NULL;

    const char * result = NULL;

    int ret = -1;


    sgx_spin_lock(&vfs_ops_lock);
    metadata = nexus_vfs_get(dirpath_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }


    if (metadata->type != NEXUS_DIRNODE) {
        log_error("path is not a directory\n");
        nexus_vfs_put(metadata);
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }


    result = __nxs_fs_readlink(metadata->dirnode, linkname_IN);

    if (result == NULL) {
        log_error("readlink FAILED\n");
        goto out;
    }


    // XXX
    strncpy(targetpath_out, result, NEXUS_PATH_MAX);

    nexus_free(result);

    ret = 0;
out:
    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}

int
__nxs_fs_hardlink(struct nexus_dirnode * link_dirnode,
                  char                 * link_filename,
                  struct nexus_dirnode * tgt_dirnode,
                  char                 * tgt_filename,
                  struct nexus_uuid    * file_uuid)
{
    nexus_dirent_type_t type;

    if (dirnode_find_by_name(tgt_dirnode, tgt_filename, &type, file_uuid)) {
        log_error("dirnode_find_by_name(%s) FAILED\n", tgt_filename);
        return -1;
    }

    if (type != NEXUS_REG) {
        log_error("NEXUS only supports hardlinking files\n");
        return -1;
    }

    {
        struct hardlink_table * hardlink_table = nexus_vfs_acquire_hardlink_table(NEXUS_FRDWR);

        if (hardlink_table == NULL) {
            log_error("nexus_vfs_acquire_hardlink_table() FAILED\n");
            return -1;
        }

        hardlink_table_incr_uuid(hardlink_table, file_uuid);

        if (nexus_vfs_flush_hardlink_table()) {
            log_error("nexus_vfs_flush_hardlink_table() FAILED\n");
            return -1;
        }
    }

    // add entry to src_dirnode
    if (dirnode_add(link_dirnode, link_filename, NEXUS_REG, file_uuid)) {
        log_error("dirnode_add(%s) FAILED\n", link_filename);
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


    sgx_spin_lock(&vfs_ops_lock);
    dst_metadata = nexus_vfs_get(dst_dirpath_IN, NEXUS_FRDWR);

    if (dst_metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
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
        sgx_spin_unlock(&vfs_ops_lock);
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

    sgx_spin_unlock(&vfs_ops_lock);
    return ret;
}

int
__nxs_fs_rename(struct nexus_dirnode    * from_dirnode,
                char                    * oldname,
                struct nexus_dirnode    * to_dirnode,
                char                    * newname,
                struct nexus_uuid       * src_uuid,
                struct nexus_fs_lookup  * overwrite_entry,
                bool                    * should_remove)
{
    nexus_dirent_type_t src_type;
    nexus_dirent_type_t tmp_type = 0;


    if (dirnode_rename(from_dirnode,
                       oldname,
                       to_dirnode,
                       newname,
                       src_uuid,
                       &src_type,
                       &overwrite_entry->uuid,
                       &overwrite_entry->type)) {
        log_error("dirnode_rename FAILED\n");
        return -1;
    }

    // for example if moving foo/bar.txt to cat/, if bar.txt already exists in cat/, we need to remove it
    if (tmp_type != 0) {
        // this means there was an existing entry in the dirnode

        // if the filenode won't be removed (hardlinks), we need to update its metadata
        if (tmp_type == NEXUS_REG) {
            if (__remove_filenode(&overwrite_entry->uuid, should_remove)) {
                log_error("__remove_filenode FAILED\n");
                return -1;
            }
        } else if (tmp_type == NEXUS_DIR) {
            __remove_dirnode(&overwrite_entry->uuid, false);
        }
    }

    return 0;
}


int
ecall_fs_rename(char                    * from_dirpath_IN,
                char                    * oldname_IN,
                char                    * to_dirpath_IN,
                char                    * newname_IN,
                struct nexus_uuid       * entry_uuid_out,
                struct nexus_fs_lookup  * overwrite_entry_out,
                bool                    * should_remove_out)
{
    struct nexus_metadata * from_metadata = NULL;
    struct nexus_metadata * to_metadata   = NULL;
    struct nexus_metadata * tmp_metadata  = NULL;

    struct nexus_dentry   * from_dentry   = NULL;
    struct nexus_dentry   * to_dentry     = NULL;

    struct nexus_uuid entry_uuid;
    struct nexus_fs_lookup existing_entry;

    bool should_remove = false;

    int ret = -1;


    sgx_spin_lock(&vfs_ops_lock);

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
        sgx_spin_unlock(&vfs_ops_lock);

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
        sgx_spin_unlock(&vfs_ops_lock);

        return -1;
    }

    if (tmp_metadata == NULL) {
        nexus_vfs_put(from_metadata);
        sgx_spin_unlock(&vfs_ops_lock);

        log_error("could not get destination metadata\n");
        return -1;
    }


    dentry_delete_child(metadata_get_dentry(from_metadata), oldname_IN);
    dentry_delete_child(metadata_get_dentry(tmp_metadata), newname_IN);

    ret = __nxs_fs_rename(from_metadata->dirnode,
                          oldname_IN,
                          tmp_metadata->dirnode,
                          newname_IN,
                          &entry_uuid,
                          &existing_entry,
                          &should_remove);

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

    nexus_uuid_copy(&entry_uuid, entry_uuid_out);
    memcpy(&overwrite_entry_out, &existing_entry, sizeof(struct nexus_fs_lookup));

    *should_remove_out = should_remove;

    ret = 0;

out:
    nexus_vfs_put(from_metadata);

    if (to_metadata) {
        nexus_vfs_put(to_metadata);
    }

    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}
