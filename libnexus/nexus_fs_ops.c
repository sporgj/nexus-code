#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/limits.h>

#include "nexus_untrusted.h"

// TODO need to create the on-disk structures
int
nexus_new(char *              dir_path,
          char *              file_name,
          nexus_fs_obj_type_t type,
          char **             nexus_name)
{
    int               ret      = -1;
    int               err      = -1;
    struct nx_inode * inode    = NULL;
    struct dirnode *  dirnode1 = NULL;
    struct dirnode *  dirnode2 = NULL;
    struct uuid       uuid;

    inode = nexus_get_inode(dir_path);
    if (inode == NULL) {
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    // generate the uuid and add to the parent dirnode
    nexus_uuid(&uuid);
    err = ecall_dirnode_add(
        global_enclave_id, &ret, dirnode1, &uuid, file_name, type);
    if (err || ret) {
        log_error("ecall_dirnode_add FAILED (err=%d, ret=%d)", err, ret);
        goto out;
    }

    err = ecall_dirnode_serialize(global_enclave_id, &ret, dirnode1, &dirnode2);
    if (err || ret) {
        log_error("ecall_dirnode_serialize FAILED (err=%d, ret=%d)", err, ret);
        goto out;
    }

    ret = nexus_flush_dirnode(inode, dirnode2);
    if (ret != 0) {
        log_error("nexus_flush_dirnode FAILED");
        goto out;
    }

    *nexus_name = filename_bin2str(&uuid);

    ret = 0;
out:
    ret |= err;

    nexus_put_inode(inode);

    return ret;
}

// TODO need to remove the on-disk structures
int
nexus_remove(char *              dir_path,
             char *              file_name,
             nexus_fs_obj_type_t type,
             char **             nexus_name)
{
    int                 ret      = -1;
    int                 err      = -1;
    nexus_fs_obj_type_t atype    = NEXUS_ANY;
    struct nx_inode *   inode    = NULL;
    struct dirnode *    dirnode1 = NULL;
    struct dirnode *    dirnode2 = NULL;
    struct uuid         uuid;

    inode = nexus_get_inode(dir_path);
    if (inode == NULL) {
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    err = ecall_dirnode_remove(
        global_enclave_id, &ret, dirnode1, file_name, &uuid, &atype);
    if (err || ret) {
        log_error("ecall_dirnode_remove FAILED (err=%d, ret=%d)", err, ret);
        goto out;
    }

    err = ecall_dirnode_serialize(global_enclave_id, &ret, dirnode1, &dirnode2);
    if (err || ret) {
        log_error("ecall_dirnode_serialize FAILED (err=%d, ret=%d)", err, ret);
        goto out;
    }

    ret = nexus_flush_dirnode(inode, dirnode2);
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
    ret |= err;

    nexus_put_inode(inode);

    return ret;
}

int
nexus_lookup(char *              dir_path,
             char *              file_name,
             nexus_fs_obj_type_t type,
             char **             nexus_name)
{
    int                 ret      = -1;
    int                 err      = -1;
    nexus_fs_obj_type_t atype    = NEXUS_ANY;
    struct nx_inode *   inode    = NULL;
    struct dirnode *    dirnode1 = NULL;
    struct uuid         uuid;

    inode = nexus_get_inode(dir_path);
    if (inode == NULL) {
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    err = ecall_dirnode_find_by_name(
        global_enclave_id, &ret, dirnode1, file_name, &uuid, &atype);
    if (err) {
        log_error(
            "ecall_dirnode_find_by_name FAILED (err=%d, ret=%d)", err, ret);
        goto out;
    }

    // if the file was not found, let's return
    if (ret != 0) {
        goto out;
    }

    *nexus_name = filename_bin2str(&uuid);
    if (*nexus_name == NULL) {
        log_error("filename_bin2str returned NULL");
        goto out;
    }

    ret = 0;
out:
    ret |= err;

    nexus_put_inode(inode);

    return ret;
}

int
nexus_filldir(char *              dir_path,
              char *              nexus_name,
              nexus_fs_obj_type_t type,
              char **             file_name)
{
    int                 ret      = -1;
    int                 err      = -1;
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

    inode = nexus_get_inode(dir_path);
    if (inode == NULL) {
        nexus_free(uuid);
        log_error("could not find inode");
        return -1;
    }

    dirnode1 = inode->dirnode;

    err = ecall_dirnode_find_by_uuid(
        global_enclave_id, &ret, dirnode1, uuid, file_name, &atype);
    if (err) {
        log_error(
            "ecall_dirnode_find_by_uuid FAILED (err=%d, ret=%d)", err, ret);
        goto out;
    }

out:
    ret |= err;

    nexus_free(uuid);
    nexus_put_inode(inode);

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
