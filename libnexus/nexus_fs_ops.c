#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nexus_internal.h"

int
nexus_new(char *              dir_path,
          char *              file_name,
          nexus_fs_obj_type_t type,
          char **             nexus_name)
{
    struct uuid uuid;

    struct nexus_metadata * metadata        = NULL;
    struct dirnode *        dirnode         = NULL;
    struct dirnode *        updated_dirnode = NULL;

    int ret = -1;

    metadata = metadata_get_metadata(dir_path);
    if (metadata == NULL) {
        log_error("could not find metadata");
        return -1;
    }

    dirnode = metadata->dirnode;

    // generate the uuid and add to the parent dirnode
    nexus_uuid(&uuid);

    ret = backend_dirnode_add(dirnode, &uuid, file_name, type);
    if (ret != 0) {
        log_error("backend_dirnode_add() FAILED");
        goto out;
    }

    ret = backend_dirnode_serialize(dirnode, &updated_dirnode);
    if (ret != 0) {
        log_error("backend_dirnode_serialize() FAILED");
        goto out;
    }

    ret = metadata_write_dirnode(metadata, updated_dirnode);
    if (ret != 0) {
        log_error("metadata_write_dirnode() FAILED");
        goto out;
    }

    // create the new metadata
    if (type == NEXUS_FILE || type == NEXUS_DIR) {
        ret = metadata_create_metadata(metadata, &uuid, type);

        if (ret != 0) {
            log_error("metadata_create_metadata FAILED");
            goto out;
        }
    }

    *nexus_name = filename_bin2str(&uuid);

    ret = 0;
out:
    metadata_put_metadata(metadata);

    return ret;
}

int
nexus_remove(char *              dir_path,
             char *              file_name,
             nexus_fs_obj_type_t type,
             char **             nexus_name)
{
    struct uuid uuid;

    nexus_fs_obj_type_t atype = NEXUS_ANY;

    struct nexus_metadata * metadata        = NULL;
    struct dirnode *        dirnode         = NULL;
    struct dirnode *        updated_dirnode = NULL;

    int ret = -1;

    metadata = metadata_get_metadata(dir_path);
    if (metadata == NULL) {
        log_error("could not find metadata");
        return -1;
    }

    dirnode = metadata->dirnode;

    ret = backend_dirnode_remove(dirnode, file_name, &uuid, &atype);
    if (ret != 0) {
        log_error("backend_dirnode_remove() FAILED");
        goto out;
    }

    ret = backend_dirnode_serialize(dirnode, &updated_dirnode);
    if (ret != 0) {
        log_error("backend_dirnode_serialize() FAILED");
        goto out;
    }

    ret = metadata_write_dirnode(metadata, updated_dirnode);
    if (ret != 0) {
        log_error("nexus_flush_dirnode FAILED");
        goto out;
    }

    ret = metadata_delete_metadata(metadata, &uuid);
    if (ret != 0) {
        log_error("metadata_delete_metadata() FAILED");
        goto out;
    }

    *nexus_name = filename_bin2str(&uuid);
    if (*nexus_name == NULL) {
        log_error("filename_bin2str returned NULL");
        goto out;
    }

    ret = 0;
out:
    metadata_put_metadata(metadata);

    return ret;
}

int
nexus_lookup(char *              dir_path,
             char *              file_name,
             nexus_fs_obj_type_t type,
             char **             nexus_name)
{
    nexus_fs_obj_type_t atype = NEXUS_ANY;

    struct nexus_metadata * metadata = NULL;
    struct dirnode *        dirnode  = NULL;
    struct uuid             uuid;

    int ret = -1;

    metadata = metadata_get_metadata(dir_path);
    if (metadata == NULL) {
        log_error("could not find metadata");
        return -1;
    }

    dirnode = metadata->dirnode;

    // if the file was not found, let's return
    ret = backend_dirnode_find_by_name(dirnode, file_name, &uuid, &atype);
    if (ret != 0) {
        log_error("backend_dirnode_find_by_name() FAILED");
        goto out;
    }

    *nexus_name = filename_bin2str(&uuid);
    if (*nexus_name == NULL) {
        log_error("filename_bin2str returned NULL");
        goto out;
    }

    ret = 0;
out:
    metadata_put_metadata(metadata);

    return ret;
}

int
nexus_filldir(char *              dir_path,
              char *              nexus_name,
              nexus_fs_obj_type_t type,
              char **             file_name)
{
    nexus_fs_obj_type_t atype = NEXUS_ANY;

    struct nexus_metadata * metadata = NULL;
    struct dirnode *        dirnode  = NULL;
    struct uuid *           uuid     = NULL;

    int ret = -1;

    // conver to UUID and search in the file
    uuid = filename_str2bin(nexus_name);
    if (uuid == NULL) {
        log_error("could not get uuid from filename");
        return -1;
    }

    metadata = metadata_get_metadata(dir_path);
    if (metadata == NULL) {
        nexus_free(uuid);
        log_error("could not find metadata");
        return -1;
    }

    dirnode = metadata->dirnode;

    ret = backend_dirnode_find_by_uuid(dirnode, uuid, file_name, &atype);
    if (ret != 0) {
        log_error("backend_dirnode_find_by_uuid() FAILED");
        goto out;
    }

    ret = 0;
out:
    nexus_free(uuid);
    metadata_put_metadata(metadata);

    return ret;
}

// TODO
int
nexus_hardlink(char * new_path, char * old_path, char ** nexus_name)
{
    return -1;
}

// TODO
int
nexus_symlink(char * target_path, char * link_path, char ** nexus_name)
{
    return -1;
}

// TODO
int
nexus_move(char *  old_dir,
           char *  old_name,
           char *  new_dir,
           char *  new_name,
           char ** old_nexus_name,
           char ** new_nexus_name)
{
    return -1;
}

// TODO
int
nexus_setacl(char * path, char * acl)
{
    return -1;
}
