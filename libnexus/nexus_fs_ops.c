#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nexus.h"

// TODO need to create the on-disk structures
int
nexus_new(char *              dir_path,
          char *              file_name,
          nexus_fs_obj_type_t type,
          char **             nexus_name)
{
#if 0
    int               ret      = -1;
    struct nx_inode * inode    = NULL;
    struct dirnode *  dirnode1 = NULL;
    struct dirnode *  dirnode2 = NULL;
    struct uuid       uuid;

    inode = vfs_get_inode(dir_path);
    if (inode == NULL) {
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    // generate the uuid and add to the parent dirnode
    nexus_uuid(&uuid);

    ret = backend_dirnode_add(dirnode1, &uuid, file_name, type);
    if (ret != 0) {
        log_error("backend_dirnode_add() FAILED");
        goto out;
    }

    ret = backend_dirnode_serialize(dirnode1, &dirnode2);
    if (ret != 0) {
        log_error("backend_dirnode_serialize() FAILED");
        goto out;
    }

    ret = vfs_flush_dirnode(inode, dirnode2);
    if (ret != 0) {
        log_error("vfs_flush_dirnode() FAILED");
        goto out;
    }

    // create the new inode 
    if (type == NEXUS_FILE || type == NEXUS_DIR) {
        ret = vfs_create_inode(
            inode, &uuid, (type == NEXUS_FILE ? NEXUS_FILEBOX : NEXUS_DIRNODE));

        if (ret != 0) {
            log_error("vfs_create_inode FAILED");
            goto out;
        }
    }

    *nexus_name = filename_bin2str(&uuid);

    ret = 0;
out:
    vfs_put_inode(inode);

    return ret;
#endif

    return 0;
}

// TODO need to remove the on-disk structures
int
nexus_remove(char *              dir_path,
             char *              file_name,
             nexus_fs_obj_type_t type,
             char **             nexus_name)
{
#if 0
    int                 ret      = -1;
    nexus_fs_obj_type_t atype    = NEXUS_ANY;
    struct nx_inode *   inode    = NULL;
    struct dirnode *    dirnode1 = NULL;
    struct dirnode *    dirnode2 = NULL;
    struct uuid         uuid;

    inode = vfs_get_inode(dir_path);
    if (inode == NULL) {
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    ret = backend_dirnode_remove(dirnode1, file_name, &uuid, &atype);
    if (ret != 0) {
        log_error("backend_dirnode_remove() FAILED");
        goto out;
    }

    ret = backend_dirnode_serialize(dirnode1, &dirnode2);
    if (ret != 0) {
        log_error("backend_dirnode_serialize() FAILED");
        goto out;
    }

    ret = vfs_flush_dirnode(inode, dirnode2);
    if (ret != 0) {
        log_error("nexus_flush_dirnode FAILED");
        goto out;
    }

    *nexus_name = filename_bin2str(&uuid);
    if (*nexus_name == NULL) {
        log_error("filename_bin2str returned NULL");
        goto out;
    }

    ret = 0;
out:
    vfs_put_inode(inode);

    return ret;
#endif

    return 0;
}

int
nexus_lookup(char *              dir_path,
             char *              file_name,
             nexus_fs_obj_type_t type,
             char **             nexus_name)
{
#if 0
    int                 ret      = -1;
    nexus_fs_obj_type_t atype    = NEXUS_ANY;
    struct nx_inode *   inode    = NULL;
    struct dirnode *    dirnode1 = NULL;
    struct uuid         uuid;

    inode = vfs_get_inode(dir_path);
    if (inode == NULL) {
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    // if the file was not found, let's return
    ret = backend_dirnode_find_by_name(dirnode1, file_name, &uuid, &atype);
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
    vfs_put_inode(inode);

    return ret;
#endif

    return 0;
}

int
nexus_filldir(char *              dir_path,
              char *              nexus_name,
              nexus_fs_obj_type_t type,
              char **             file_name)
{
#if 0
    int                 ret      = -1;
    nexus_fs_obj_type_t atype    = NEXUS_ANY;
    struct nx_inode *   inode    = NULL;
    struct dirnode *    dirnode1 = NULL;
    struct uuid *       uuid     = NULL;

    // conver to UUID and search in the file
    uuid = filename_str2bin(nexus_name);
    if (uuid == NULL) {
        log_error("could not get uuid from filename");
        return -1;
    }

    inode = vfs_get_inode(dir_path);
    if (inode == NULL) {
        nexus_free(uuid);
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    ret = backend_dirnode_find_by_uuid(dirnode1, uuid, file_name, &atype);
    if (ret != 0) {
        log_error("backend_dirnode_find_by_uuid() FAILED");
        goto out;
    }

    ret = 0;
out:
    nexus_free(uuid);
    vfs_put_inode(inode);

    return ret;
#endif

    return 0;
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
