#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...)                                                    \
    printk(KERN_ERR "ucafs_dirops(%s): " fmt, __FUNCTION__, ##args)

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
