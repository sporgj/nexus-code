#ifdef AFS_SECURE

#include "ucafs_kern.h"

static char * watch_dirs[] = { "/maatta.sgx/user/bruyne/sgx" };

struct rx_connection * conn = NULL, *ping_conn = NULL;

int AFSX_IS_CONNECTED = 0;

int LINUX_AFSX_connect()
{
    u_long host;
    struct rx_securityClass * null_securityObject;

    rx_Init(0);

    /* set the address to the current machine */
    host = htonl(INADDR_LOOPBACK);
    null_securityObject = rxnull_NewClientSecurityObject();
    conn = rx_NewConnection(host, AFSX_SERVER_PORT, AFSX_SERVICE_ID,
                            null_securityObject, AFSX_NULL);
    ping_conn = rx_NewConnection(host, AFSX_SERVER_PORT, AFSX_SERVICE_ID,
                                 null_securityObject, AFSX_NULL);

    rx_SetConnDeadTime(conn, 5);
    rx_SetConnHardDeadTime(ping_conn, 2);

    if (conn == NULL || ping_conn == NULL) {
        /* maybe have a retry */
        printk(KERN_ERR "Connection to AFSX server failed\n");
        return -1;
    }
    return 0;
}

int LINUX_AFSX_ping(void)
{
    int ret, dummy;

    /* lower the timeout, 2 */
    ret = AFSX_fversion(ping_conn, 0, &dummy);

    dummy = AFSX_IS_CONNECTED;
    AFSX_IS_CONNECTED = (ret == 0);
    if (dummy != AFSX_IS_CONNECTED) {
        printk(KERN_ERR "connected: %d, ret = %d\n", AFSX_IS_CONNECTED, ret);
    }
    return 0;
}

struct rx_connection * __get_conn(void)
{
    u_long host;
    struct rx_securityClass * null_securityObject;

    host = htonl(INADDR_LOOPBACK);
    null_securityObject = rxnull_NewClientSecurityObject();
    conn = rx_NewConnection(host, AFSX_SERVER_PORT, AFSX_SERVICE_ID,
                            null_securityObject, AFSX_NULL);

    rx_GetConnection(conn);
    return conn;
}

void __put_conn(struct rx_connection * c) { rx_PutConnection(c); }

/**
 * whether to ignore a vnode or not.
 * if not ignore, dest will be set to the full path of the directory
 *
 * @return bool true if path is to be ignored
 */
int __is_dentry_ignored(struct dentry * dentry, char ** dest)
{
    int len, i;
    char * path, *curr_dir, *result;
    char buf[512];

    // TODO cache the inode number
    path = dentry_path_raw(dentry, buf, sizeof(buf));

    for (i = 0; i < sizeof(watch_dirs) / sizeof(char *); i++) {
        curr_dir = watch_dirs[i];

        if (strnstr(path, curr_dir, strlen(curr_dir))) {
            // TODO maybe check the prefix on the name
            // we're good
            if (dest) {
                len = strlen(path);
                result = kmalloc(len + 1, GFP_KERNEL);
                memcpy(result, path, len);
                result[len] = '\0';
                *dest = result;
            }
            return 0;
        }
    }
    return 1;
}

inline int __is_vnode_ignored(struct vcache * avc, char ** dest)
{
    return __is_dentry_ignored(d_find_alias(AFSTOV(avc)), dest);
}

int UCAFS_create(char ** dest, int is_file, struct dentry * dp)
{
    int ret;
    char * fpath;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    ret = AFSX_fnew(conn, fpath, dest);
    if (ret) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "error on file %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_realname(char ** dest, char * fname, struct dentry * dp)
{
    int ret;
    char * dirpath;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_dentry_ignored(dp, &dirpath)) {
        return AFSX_STATUS_NOOP;
    }

    if ((ret = AFSX_frealname(conn, fname, dirpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "realname error: %s\n", dirpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_lookup(char ** dest, struct dentry * dp)
{
    int ret;
    char * fpath;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    if ((ret = AFSX_fencodename(conn, fpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "lookup error: %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_delfile(char ** dest, struct dentry * dp)
{
    int ret;
    char * fpath;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    if ((ret = AFSX_fremove(conn, fpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "delete error: %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

#if 0
// TODO test function
int LINUX_AFSX_rename(char ** dest, struct dentry * from_dp, struct dentry * to_dp)
{
    int ret, ignore_from, ignore_to;
    char * from_path, to_path;

    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    ignore_from = __is_dentry_ignored(from_dp, from_path);
    ignore_to = __is_dentry_ignored(to_dp, to_path);

    // TODO finish code for moving across protected folders
    // for now, just support within one folder
    if (ignore_from || ignore_to) {
        return AFSX_STATUS_NOOP;
    }

    return 0;
}
#endif

#define MAX_NUM_OF_CHUNKS 32
#endif
