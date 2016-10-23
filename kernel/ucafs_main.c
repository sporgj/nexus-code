#ifdef AFS_SECURE
#include "ucafs_kern.h"
#include <linux/dcache.h>

static const char * afs_prefix = "/afs";
static const uint32_t afs_prefix_len = 4;

static char * watch_dirs[] = { "/maatta.sgx/user/bruyne/sgx" };
static const int watch_dir_len[] = { sizeof(watch_dirs[0]) - 1 };

struct rx_connection *conn = NULL, *ping_conn = NULL;

int AFSX_IS_CONNECTED = 0;

int
LINUX_AFSX_connect()
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
    rx_SetConnDeadTime(ping_conn, 2);

    if (conn == NULL || ping_conn == NULL) {
        /* maybe have a retry */
        printk(KERN_ERR "Connection to AFSX server failed\n");
        return -1;
    }
    return 0;
}

int
LINUX_AFSX_ping(void)
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

struct rx_connection *
__get_conn(void)
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

void
__put_conn(struct rx_connection * c)
{
    rx_PutConnection(c);
}

static inline ucafs_entry_type
dentry_type(struct dentry * dentry)
{
    if (d_is_file(dentry)) {
        return UCAFS_TYPE_FILE;
    } else if (d_is_dir(dentry)) {
        return UCAFS_TYPE_DIR;
    } else if (d_is_symlink(dentry)) {
        return UCAFS_TYPE_LINK;
    }

    return UCAFS_TYPE_UNKNOWN;
}

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre), lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

/**
 * whether to ignore a vnode or not.
 * if not ignore, dest will be set to the full path of the directory
 *
 * @return bool true if path is to be ignored
 */
int
__is_dentry_ignored(struct dentry * dentry, char ** dest)
{
    int len, i, total_len;
    char *path, *curr_dir, *result;
    char buf[512];

    /* TODO cache the inode number
    printk(KERN_ERR "\npar=%p, dentry=%p, iname=%s d_name.len=%d dentry_name=%s",
           dentry->d_parent, dentry, dentry->d_iname, dentry->d_name.len,
           dentry->d_name.name); */
    path = dentry_path_raw(dentry, buf, sizeof(buf));

    if (IS_ERR_OR_NULL(path)) {
        return 1;
    }

    /*
    printk(KERN_ERR "path=%p\n", path);
    print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf, sizeof(buf),
                   1); */

    for (i = 0; i < sizeof(watch_dirs) / sizeof(char *); i++) {
        curr_dir = watch_dirs[i];

        if (startsWith(curr_dir, path)) {
            // TODO maybe check the prefix on the name
            // we're good
            if (dest) {
                len = strlen(path);
                total_len = afs_prefix_len + len;
                result = kmalloc(total_len + 1, GFP_KERNEL);
                memcpy(result, afs_prefix, afs_prefix_len);
                memcpy(result + afs_prefix_len, path, len);
                result[total_len] = '\0';
                *dest = result;
            }
            return 0;
        }
    }
    return 1;
}

inline int
UCAFS_ignore_dentry(struct dentry * dp, char ** dest)
{
    return __is_dentry_ignored(dp, dest);
}

inline int
__is_vnode_ignored(struct vcache * avc, char ** dest)
{
    return __is_dentry_ignored(d_find_alias(AFSTOV(avc)), dest);
}

int
UCAFS_create(char ** dest, ucafs_entry_type type, struct dentry * dp)
{
    int ret;
    char * fpath;
    struct rx_connection * conn = NULL;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    conn = __get_conn();

    ret = AFSX_create(conn, fpath, type, dest);
    if (ret) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "error on file %s\n", fpath);
        }
        *dest = NULL;
    }

    __put_conn(conn);
    kfree(fpath);
    return ret;
}

int
UCAFS_find(char ** dest, char * fname, ucafs_entry_type type, char * dirpath)
{
    int ret;
    struct rx_connection * conn = NULL;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    conn = __get_conn();

    if ((ret = AFSX_find(conn, fname, dirpath, type, dest))) {
        *dest = NULL;
    }

    __put_conn(conn);
    return ret;
}

int
UCAFS_lookup(char ** dest, struct dentry * dp)
{
    int ret;
    char * fpath;
    struct rx_connection * conn = NULL;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if (dp->d_name.len > 100) {
        return -1;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    conn = __get_conn();

    if ((ret = AFSX_lookup(conn, fpath, dentry_type(dp), dest))) {
        *dest = NULL;
    }

    __put_conn(conn);
    kfree(fpath);
    return ret;
}

int
UCAFS_remove(char ** dest, struct dentry * dp)
{
    int ret;
    char * fpath;
    struct rx_connection * conn = NULL;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if (__is_dentry_ignored(dp, &fpath)) {
        return AFSX_STATUS_NOOP;
    }

    conn = __get_conn();

    if ((ret = AFSX_remove(conn, fpath, dentry_type(dp), dest))) {
        *dest = NULL;
    }

    __put_conn(conn);
    kfree(fpath);
    return ret;
}

int
UCAFS_rename(char ** dest, struct dentry * from_dp, struct dentry * to_dp)
{
    int ret = AFSX_STATUS_NOOP, ignore_from, ignore_to;
    char *from_path = NULL, *to_path = NULL;
    struct rx_connection * conn = NULL;

    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    ignore_from = __is_dentry_ignored(from_dp, &from_path);
    ignore_to = __is_dentry_ignored(to_dp, &to_path);

    printk(KERN_ERR "renaming: %s -> %s\n", from_path, to_path);

    if (ignore_from && ignore_to) {
        goto out;
    }

    conn = __get_conn();

    *dest = NULL;
    if ((ret
         = AFSX_rename(conn, from_path, to_path, dentry_type(from_dp), dest))) {
    }

    __put_conn(conn);
out:
    if (from_path)
        kfree(from_path);
    if (to_path)
        kfree(to_path);

    return ret;
}

#endif
