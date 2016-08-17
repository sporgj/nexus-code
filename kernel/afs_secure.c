#ifdef AFS_SECURE
#include <linux/in.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/string.h>

#include <afsconfig.h>
#include "afs/param.h"

#include "afs/sysincludes.h"
#include "afsincludes.h"
#include "afs_secure.h"
#include "afsx.h"

static char * ignore_dirs[] = { "/xyz.vm/user/mirko/.afsx" };

static struct rx_connection * conn = NULL, *ping_conn = NULL;

static int AFSX_IS_CONNECTED = 0;

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
    rx_SetConnDeadTime(ping_conn, 2);

    if (conn == NULL || ping_conn == NULL) {
        /* maybe have a retry */
        printk(KERN_ERR "Connection to AFSX server failed\n");
        return -1;
    }
    LINUX_AFSX_ping();
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

/**
 * whether to ignore a vnode or not.
 * if not ignore, dest will be set to the full path of the directory
 *
 * @return bool true if path is to be ignored
 */
static int __ignore_vnode(struct vcache * avc, char ** dest)
{
    int ret, len;
    char * path, *result;
    char buf[512];
    struct inode * inode = AFSTOV(avc);

    // TODO cache the inode number
    path = dentry_path_raw(d_find_alias(inode), buf, sizeof(buf));

    if ((ret = (LINUX_AFSX_ignore_path_bool(path))) && dest) {
        len = strlen(path);
        result = kmalloc(len + 1);
        memcpy(result, path, len);
        result[len + 1] = '\0';
        *dest = result;
    }

    return ret;
}

/**
 * return 0
 */
int LINUX_AFSX_ignore_path_bool(char * dir)
{
    int i;
    int len;
    char * ignore;

    for (i = 0; i < sizeof(ignore_dirs) / sizeof(char *); i++) {
        ignore = ignore_dirs[i];
        len = strlen(ignore);
        if (strnstr(dir, ignore, len + 1)) {
            return 1;
        }
    }
    return 0;
}

int LINUX_AFSX_newfile(char ** dest, char * fpath)
{
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
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

int LINUX_AFSX_realname(char ** dest, char * fname, char * dirpath)
{
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if ((ret = AFSX_frealname(conn, fname, dirpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "realname error: %s\n", dirpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_lookup(char ** dest, char * fpath)
{
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if ((ret = AFSX_fencodename(conn, fpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "lookup error: %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_delfile(char ** dest, char * fpath)
{
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if ((ret = AFSX_fremove(conn, fpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "delete error: %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

#define MAX_NUM_OF_CHUNKS 32

/**
 * Stores all the chunks attached to a vcache
 *
 * @return 0 on success
 */
int LINUX_AFSX_push_file(struct vcache * avc)
{
    struct dcache * tdc, **dclist;
    int hash, index, ret = -1, count = 0, j;
    afs_size_t size, tlen, offset;
    char * path = NULL;
    afs_size_t total_len;
    struct rx_call * sgx_call, * afs_call;
    struct osi_file * file;
    void * buffer = (void *)__get_free_page(GFP_KERNEL);

    if (__ignore_vnode(avc, &path)) {
        return 0;
    }

    total_len = avc->f.m.Length;

    // hash value of the vnode's dcache list
    hash = DVHash(&avc->f.fid);

    // XXX assuming that the prototype used does not employ a memory cache.
    dclist = (struct dcache **)get_zeroed_page(GFP_KERNEL);

    ObtainWriteLock(&afs_xdcache, 6503);
    sgx_call = rx_newCall(conn);
    if (StartAFSX_fpush(sgx_call, path, 0, total_len))
        return -1;

    for (index = afs_dvhashTbl[hash], j = 0;
         j < MAX_NUM_OF_CHUNKS && index != NULLIDX; j++) {
        // make sure we have a valid entry
        if (afs_indexUnique[index] == avc->f.fid.Fid.Unique) {
            tdc = afs_GetValidDSlot(index); // refcount + 1
            // printk(KERN_ERR "index = %d\n", index);

            if (tdc) {
                if (!FidCmp(&tdc->f.fid, &avc->f.fid)) {
                    // add it to the list of dcaches
                    dclist[tdc->f.chunk] = tdc;
                    printk(KERN_ERR "Found a tdc: %p\n", tdc);
                    count++;

                    // read from the file
                    size = tdc->f.size;
                    tlen = PAGE_SIZE;
                    file = afs_CFileOpen(&tdc->f.inode);
                    while (size) {
                        tlen = afs_osi_read(file, -1, buffer, tlen);

                        // send the data over to userspace
                        rx_Write(sgx_call, buffer, tlen);

                        // wait for the response
                        rx_Read(sgx_call, buffer, tlen);

                        size -= tlen;
                    }
                    afs_CFileClose(file);
                }

                ReleaseReadLock(&tdc->tlock);
                afs_PutDCache(tdc);
            }
        }
        index = afs_dvnextTbl[index];
    }

    ret = rx_EndCall(sgx_call, ret);

    printk(KERN_ERR "Number: %d, Path: %s\n", count, path);
    if (path) {
        kfree(path);
    }
    __free_page(buffer);
    ReleaseWriteLock(&afs_xdcache);
    return ret;
}

#endif
