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

static char * ignore_dirs[] = { "/maatta.sgx/user/bruyne/.afsx" };

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
static int __is_vnode_ignored(struct vcache * avc, char ** dest)
{
    int ret, len;
    char * path, *result;
    char buf[512];
    struct inode * inode = AFSTOV(avc);

    // TODO cache the inode number
    path = dentry_path_raw(d_find_alias(inode), buf, sizeof(buf));

    if (!(ret = LINUX_AFSX_ignore_path_bool(path)) && dest) {
        len = strlen(path);
        result = kmalloc(len + 1, GFP_KERNEL);
        memcpy(result, path, len);
        result[len] = '\0';
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

int LINUX_AFSX_upload_file(struct vcache * avc, struct vrequest * areq)
{
    int ret = -1, hash, i = 0, index, code;
    afs_uint32 size, dcache_size, remaining_bytes, total_len, upload_id, nbytes;
    char * path = NULL;
    void * buffer = NULL;
    struct dcache * tdc = NULL;
    struct rx_connection * rx_conn;
    struct rx_call * uspace_call = NULL, *afs_call = NULL;
    struct osi_file * file = NULL;
    struct afs_conn * tc;
    struct AFSVolSync tsync;
    struct AFSFetchStatus outstatus;
    struct AFSStoreStatus instatus;

    if (!AFSX_IS_CONNECTED) {
        printk(KERN_ERR "upload: not connected\n");
        return AFSX_STATUS_NOOP;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    // if it's not dirty, ignore
    if (!(avc->f.states & CDirty)) {
        return AFSX_STATUS_SUCCESS;
    }

    // anything hereon is a fatal error
    ret = AFSX_STATUS_ERROR;

    buffer = (void *)__get_free_page(GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Could not allocate buffer\n");
        return ret;
    }

    total_len = avc->f.m.Length;
    hash = DVHash(&avc->f.fid);

    // 1 - Get the Lock and start the upload
    ObtainWriteLock(&afs_xdcache, 6503);

    tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn);
    afs_call = rx_NewCall(tc->id);

    //RX_AFS_GLOCK();
    instatus.Mask = AFS_SETMODTIME;
    instatus.ClientModTime = avc->f.m.Date;
    //RX_AFS_GUNLOCK();

#ifdef AFS_64BIT_CLIENT
    // if the server is rrunning in 64 bits
    if (!afs_serverHasNo64Bit(tc)) {
        code = StartRXAFS_StoreData64(afs_call, (struct AFSFid *)&avc->f.fid.Fid,
                                     &instatus, 0, total_len, total_len);
    } else {
        // XXX check for total_len > 2^32 - 1
        code = StartRXAFS_StoreData(afs_call, (struct AFSFid *)&avc->f.fid.Fid,
                                   &instatus, (afs_int32)0,
                                   (afs_int32)total_len, (afs_int32)total_len);
    }
#else
    code = StartRXAFS_StoreData64(afs_call, (struct AFSFid *)&avc->f.fid.Fid,
                                 &instatus, 0, total_len, total_len);
#endif

    if (code) {
        rx_EndCall(afs_call, 0);
        afs_call = NULL;
        printk(KERN_ERR "rxafs_store failed\n");
        goto out;
    }

    if (AFSX_start_upload(conn, path, AFSX_PACKET_SIZE, total_len,
                          &upload_id)) {
        printk(KERN_ERR "start_upload failed: %s\n", path);
        goto out;
    }

    remaining_bytes = total_len;
    index = afs_dvhashTbl[hash];

    // 2 - Send the current dcache
    while ((index != NULLIDX)
           && (afs_indexUnique[index] == avc->f.fid.Fid.Unique)) {
        if ((tdc = afs_GetValidDSlot(index))
            && !FidCmp(&tdc->f.fid, &avc->f.fid)) {
            dcache_size = tdc->f.chunkBytes;

            file = (struct osi_file *)osi_UFSOpen(&tdc->f.inode);
            while (dcache_size) {
                size = dcache_size > AFSX_PACKET_SIZE ? AFSX_PACKET_SIZE
                                                      : dcache_size;

                code = afs_osi_Read(file, -1, buffer, AFSX_PACKET_SIZE);

                /* XXX for some reason, I'm getting an error reading from
                the file
                 * but the data is read in the buffer. TO BE INVESTIGATED
                if (code < 0) {
                    printk(
                        KERN_ERR
                        "upload: Error reading chunk #%d, ret=%d, off=%u,
                size=%u\n",
                        i, code, file->offset, size);
                    goto out1;
                }
                */

                // 3 - Sending it over to userspace
                uspace_call = rx_NewCall(conn);

                if (StartAFSX_upload_file(uspace_call, upload_id, size)) {
                    printk(KERN_ERR "StartAFSX_upload_file failed");
                    goto out1;
                }

                if ((nbytes = rx_Write(uspace_call, buffer, size)) != size) {
                    printk(KERN_ERR "send error: exp=%d, act=%u\n", size,
                           nbytes);
                    goto out1;
                }

                if ((nbytes = rx_Read(uspace_call, buffer, size)) != size) {
                    printk(KERN_ERR "recv error: exp=%d, act=%u\n", size,
                           nbytes);
                    goto out1;
                }

                // 4 - Send the data over to the server
                if ((nbytes = rx_Write(afs_call, buffer, size)) != size) {
                    printk(KERN_ERR "send to server failed: exp=%d, act=%d\n",
                            size, (int)nbytes);
                    goto out1;
                }

                dcache_size -= size;
                EndAFSX_upload_file(uspace_call);
                rx_EndCall(uspace_call, 0);
            }
            osi_UFSClose(file);

            uspace_call = NULL;
            // release the tdc resources
            ReleaseReadLock(&tdc->tlock);
            afs_PutDCache(tdc);
            tdc = NULL;
        } else {
            printk(KERN_ERR "hash chain failed us :( index=%d, i=%d)\n", index, i);
            goto out1;
        }

        i++;
        index = afs_dvnextTbl[index];
    }

    ret = 0;
out1:
    if (ret == AFSX_STATUS_ERROR) {
        if (uspace_call) {
            EndAFSX_upload_file(uspace_call);
            rx_EndCall(uspace_call, 0);
        }

        if (tdc) {
            afs_CFileClose(file);
            ReleaseReadLock(&tdc->tlock);
            afs_PutDCache(tdc);
        }
    }
out:
    ReleaseWriteLock(&afs_xdcache);
    if (afs_call) {
#ifdef AFS_64BIT_CLIENT
        EndRXAFS_StoreData64(afs_call, &outstatus, &tsync);
#else
        EndRXAFS_StoreData(afs_call, &outstatus, &tsync);
#endif
        rx_EndCall(afs_call, 0);
    }
    AFSX_end_upload(conn, upload_id);
    if (buffer)
        __free_page(buffer);
    if (path)
        kfree(path);

    return ret;
}

/*
int LINUX_AFSX_get_file(struct vcache * avc)
{
    int ret = AFSX_STATUS_ERROR;
    afs_uint32 total_len, get_id;

    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_vnode_ignore(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    buffer = (void *)__get_free_page(GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "download_file: Could not allocate free page\n");
        goto out;
    }

    total_len = avc->f.m.Length;

out:
    return ret;
}
*/
#endif
