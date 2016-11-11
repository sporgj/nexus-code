#include "ucafs_kern.h"
#include <linux/dcache.h>

static const char * afs_prefix = "/afs";
static const uint32_t afs_prefix_len = 4;

static char * watch_dirs[] = { UC_AFS_PATH_KERN"/"UC_AFS_WATCH };
static const int watch_dir_len[] = { sizeof(watch_dirs[0]) - 1 };

struct rx_connection *conn = NULL, *ping_conn = NULL;

int UCAFS_IS_CONNECTED = 0;

int
ucafs_connect(void)
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

    printk(KERN_ERR "watch: %s\n", watch_dirs[0]);

    if (conn == NULL || ping_conn == NULL) {
        /* maybe have a retry */
        printk(KERN_ERR "Connection to AFSX server failed\n");
        return -1;
    }
    return 0;
}

int
ucafs_ping(void)
{
    int ret, dummy;

    /* lower the timeout, 2 */
    ret = AFSX_fversion(ping_conn, 0, &dummy);

    dummy = UCAFS_IS_CONNECTED;
    UCAFS_IS_CONNECTED = (ret == 0);
    if (dummy != UCAFS_IS_CONNECTED) {
        printk(KERN_ERR "connected: %d, ret = %d\n", UCAFS_IS_CONNECTED, ret);
    }
    return 0;
}

char *
uc_mkpath(const char * parent_path, const char * fname)
{
    int len1 = strlen(parent_path), len2 = strlen(fname);
    char * rv = (char *)kmalloc(len1 + len2 + 2, GFP_KERNEL);
    memcpy(rv, parent_path, len1);
    rv[len1] = '/';
    memcpy(rv + len1 + 1, fname, len2);
    rv[len1 + len2 + 1] = '\0';

    return rv;
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

inline ucafs_entry_type
uc_vnode_type(struct vcache * vnode)
{
    if (vnode == NULL) {
        return UC_ANY;
    }

    switch(vType(vnode)) {
        case VREG: return UC_FILE;
        case VDIR: return UC_DIR;
        case VLNK: return UC_LINK;
    }

    return UC_ANY;
}

inline ucafs_entry_type
dentry_type(struct dentry * dentry)
{
    if (d_is_file(dentry)) {
        return UC_FILE;
    } else if (d_is_dir(dentry)) {
        return UC_DIR;
    } else if (d_is_symlink(dentry)) {
        return UC_LINK;
    }

    return UC_ANY;
}

inline ucafs_entry_type
vnode_type(struct vcache * avc)
{
    return dentry_type(d_find_alias(AFSTOV(avc)));
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
    printk(KERN_ERR "\npar=%p, dentry=%p, iname=%s d_name.len=%d
    dentry_name=%s",
           dentry->d_parent, dentry, dentry->d_iname, dentry->d_name.len,
           dentry->d_name.name); */
    path = dentry_path_raw(dentry, buf, sizeof(buf));

    if (IS_ERR_OR_NULL(path)) {
        print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf,
                       sizeof(buf), 1);
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
    // if it's null, just ignore it
    if (avc == NULL) {
        return 1;
    }

    return __is_dentry_ignored(d_find_alias(AFSTOV(avc)), dest);
}

inline int
ucafs_vnode_path(struct vcache * avc, char ** dest)
{
    return __is_vnode_ignored(avc, dest);
}

