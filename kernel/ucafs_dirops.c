#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...)                                                    \
    printk(KERN_ERR "ucafs_dirops(%s): " fmt, __FUNCTION__, ##args)

int
ucafs_rename(struct vcache * from_vnode,
             char * oldname,
             struct vcache * to_vnode,
             char * newname,
             char ** old_shadowname,
             char ** new_shadowname)
{
    int ret;
    char *from_path = NULL, *to_path = NULL;
    struct rx_connection * uc_conn = NULL;
    int ignore_from, ignore_to;

    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    ignore_from = ucafs_vnode_path(from_vnode, &from_path);
    ignore_to = ucafs_vnode_path(to_vnode, &to_path);

    if (ignore_from && ignore_to) {
        goto out;
    }

    printk(KERN_ERR "renaming: %s -> %s\n", from_path, to_path);

    uc_conn = __get_conn();

    ret = AFSX_rename(conn, from_path, oldname, to_path, newname,
                      vnode_type(from_vnode), old_shadowname, new_shadowname);
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
ucafs_rename2(char * dirpath,
              char * oldname,
              char * newname,
              ucafs_entry_type type,
              char ** dest)
{
    int ret;
    struct rx_connection * uc_conn;

    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    uc_conn = __get_conn();

    ret = AFSX_sillyrename(uc_conn, dirpath, oldname, newname, type, dest);
    if (ret) {
        *dest = NULL;
    }

    __put_conn(uc_conn);

    return ret;
}

int
ucafs_remove2(char * parent_path,
              char * file_name,
              ucafs_entry_type type,
              char ** dest)
{
    int ret;
    char * fpath;
    struct rx_connection * uc_conn;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    ERROR("parent_path=%s, fname=%s\n", parent_path, file_name);

    uc_conn = __get_conn();
    fpath = uc_mkpath(parent_path, file_name);

    if ((ret = AFSX_remove(uc_conn, fpath, type, dest))) {
        kfree(*dest);
        *dest = NULL;
    }

    __put_conn(uc_conn);
    kfree(fpath);
    return ret;
}

int
ucafs_plain2code(char * parent_path,
                 char * plain_file_name,
                 ucafs_entry_type type,
                 char ** dest)
{
    int ret;
    char * fpath;
    struct rx_connection * uc_conn;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    ERROR("parent_path:%s, fname:%s\n", parent_path, plain_file_name);

    uc_conn = __get_conn();
    fpath = uc_mkpath(parent_path, plain_file_name);

    if ((ret = AFSX_lookup(uc_conn, fpath, type, dest))) {
        kfree(*dest);
        *dest = NULL;
    }

    __put_conn(uc_conn);
    kfree(fpath);

    return ret;
}
