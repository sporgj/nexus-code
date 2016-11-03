#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...)                                                    \
    printk(KERN_ERR "ucafs_dirops(%s): " fmt, __FUNCTION__, ##args)

int
ucafs_create(struct vcache * parent_vnode,
             char * name,
             ucafs_entry_type type,
             char ** shadow_name_dest)
{
    int ret, ignore;
    char * path;
    struct rx_connection * uc_conn = NULL;

    if (!UCAFS_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    ignore = ucafs_vnode_path(parent_vnode, &path);
    if (ignore) {
        return AFSX_STATUS_NOOP;
    }

    uc_conn = __get_conn();

    ret = AFSX_create1(uc_conn, path, name, type, shadow_name_dest);
    if (ret) {
        kfree(*shadow_name_dest);
    }

    __put_conn(uc_conn);
    return ret;
}

int
ucafs_rename(struct vcache * from_vnode,
             char * oldname,
             struct vcache * to_vnode,
             char * newname,
             char ** old_shadowname,
             char ** new_shadowname)
{
    int ret = AFSX_STATUS_NOOP;
    char *from_path = NULL, *to_path = NULL;
    struct rx_connection * uc_conn = NULL;
    int ignore_from, ignore_to;

    if (!UCAFS_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    ignore_from = ucafs_vnode_path(from_vnode, &from_path);
    ignore_to = ucafs_vnode_path(to_vnode, &to_path);

    if (ignore_from && ignore_to) {
        goto out;
    }

    uc_conn = __get_conn();

    ret = AFSX_rename(conn, from_path, oldname, to_path, newname, UC_ANY,
                      old_shadowname, new_shadowname);
    if (ret) {
        kfree(*old_shadowname);
        kfree(*new_shadowname);
    }

    __put_conn(uc_conn);
out:
    if (from_path)
        kfree(from_path);
    if (to_path)
        kfree(to_path);

    return ret;
}

int
ucafs_find(char * parent_path,
           char * shadow_name,
           ucafs_entry_type type,
           char ** dest)
{
    int ret;
    struct rx_connection * uc_conn;

    *dest = NULL;
    if (!UCAFS_IS_CONNECTED) {
        return -1;
    }

    uc_conn = __get_conn();
    if ((ret = AFSX_find(uc_conn, shadow_name, parent_path, type, dest))) {
        if (*dest != NULL) {
            kfree(*dest);
        }
    }

    __put_conn(uc_conn);
    return ret;
}

int
ucafs_lookup(struct vcache * parent_vnode,
                 char * plain_file_name,
                 ucafs_entry_type type,
                 char ** dest)
{
    int ret, ignore;
    char * fpath, * parent_path;
    struct rx_connection * uc_conn;

    if (!UCAFS_IS_CONNECTED) {
        return -1;
    }

    ignore = ucafs_vnode_path(parent_vnode, &parent_path);
    if (ignore) {
        return AFSX_STATUS_NOOP;
    }

    uc_conn = __get_conn();
    fpath = uc_mkpath(parent_path, plain_file_name);

    *dest = NULL;
    if ((ret = AFSX_lookup(uc_conn, fpath, type, dest))) {
        kfree(*dest);
        *dest = NULL;
    }

    __put_conn(uc_conn);
    kfree(fpath);
    kfree(parent_path);

    return ret;
}

int
ucafs_hardlink(struct dentry * olddp, struct dentry * newdp, char ** dest)
{
    int ret = AFSX_STATUS_NOOP;

    int ignore_from, ignore_to;
    char *from_path = NULL, *to_path = NULL;
    struct rx_connection * conn = NULL;

    if (!UCAFS_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    ignore_from = __is_dentry_ignored(olddp, &from_path);
    ignore_to = __is_dentry_ignored(newdp, &to_path);

    if (ignore_from && ignore_to) {
        goto out;
    }

    conn = __get_conn();

    *dest = NULL;
    if ((ret = AFSX_hardlink(conn, from_path, to_path, dest))) {
        kfree(*dest);
    }

    __put_conn(conn);
out:
    if (from_path)
        kfree(from_path);
    if (to_path)
        kfree(to_path);

    return ret;
}

int
ucafs_softlink(struct dentry * dp, char * target, char ** dest)
{
    int ret;
    char * fpath;
    struct rx_connection * conn = NULL;

    *dest = NULL;
    if (!UCAFS_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    conn = __get_conn();

    ret = AFSX_softlink(conn, fpath, target, dest);
    if (ret) {
        kfree(*dest);
        *dest = NULL;
    }

    __put_conn(conn);
    kfree(fpath);
    return ret;
}
