#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_fbox: " fmt, ##args)

#undef DEBUG
#define DEBUG(fmt, args...) printk(KERN_ERR "ucafs_fbox (debug): " fmt, ##args)

static int
_ucafs_read_fbox(struct rx_call * acall, afs_int32 length, uc_fbox_t ** p_fbox)
{
    int code, nbytes, abytes, pos, srv_64bit;
    uc_fbox_t temp_fbox, *fbox = NULL;

    if (length <= sizeof(temp_fbox)) {
        goto done;
    }

    /* we can now start reading */
    nbytes = rx_Read(acall, (char *)&temp_fbox, FBOX_HEADER_LEN);
    if (nbytes != FBOX_HEADER_LEN) {
        code = -1;
        goto done;
    }

    if (temp_fbox.magic != UCAFS_FBOX_MAGIC) {
        goto done;
    }

    if (fbox == NULL
        && (fbox = kmalloc(temp_fbox.fbox_len, GFP_KERNEL)) == NULL) {
        /* XXX should we have a flag to stop the loop?
         * An allocation error is not the RPC's fault */
        ERROR("allocating fbox failed\n");
        goto done;
    }

    memcpy(fbox, (char *)&temp_fbox, nbytes);

    /* do we have to read more ? */
    pos = nbytes;
    nbytes = temp_fbox.fbox_len - nbytes;
    if (nbytes > 0) {
        if ((abytes = rx_Read(acall, (char *)(fbox + pos), nbytes)) != nbytes) {
            code = -1;
            ERROR("reading from fserver failed. exp=%d, act=%d\n", (int)nbytes,
                  abytes);
            goto done;
        }
    }

    code = 0;
done:
    if (code && fbox) {
        kfree(fbox);
        fbox = NULL;
    }

    p_fbox = fbox;
    return code;
}

/**
 * Reads the fbox of the avc file by sending a request to the server
 * and getting the data
 *
 * @param avc is the avc to read from; make sure you check the file is
 * a tdc
 */
int
ucafs_fbox(struct vcache * avc, uc_fbox_t ** p_fbox)
{
    int ret = AFSX_STATUS_NOOP, code = 0;
    struct afs_conn * tc = NULL;
    struct rx_connection * rxconn = NULL;
    struct rx_call * acall = NULL;
    struct afs_FetchOutput tsmall;
    struct vrequest * areq;
    cred_t * credp = NULL;
    afs_int32 length;
    char * path = NULL;

    if (!UCAFS_IS_CONNECTED || vType(avc) == VDIR) {
        return ret;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return ret;
    }

    credp = crref();
    if (afs_CreateReq(&areq, credp)) {
        ERROR("afs_createReq returns = %d\n", code);
        goto out;
    }

    /* 1 - Connect to the AFS server */
    do {
        if ((tc = afs_Conn(&avc->f.fid, areq, SHARED_LOCK, &rxconn)) == NULL) {
            ERROR("afs_Conn returned null\n");
            goto out;
        }

        code = _ucafs_init_fetch(tc, rxconn, avc, 0, 0x7FFFFFF, &length,
                                 &srv_64bit, &acall);
        if (code) {
            ERROR("initializing fetch failed\n");
            goto done;
        }

        code = _ucafs_read_fbox(acall, p_fbox);

        /* lets free the afs call */
        code = _ucafs_end_fetch(acall, &tsmall, srv_64bit, code);
        acall = NULL;
    } while (afs_Analyze(tc, rxconn, code, &avc->f.fid, areq,
                         AFS_STATS_FS_RPCIDX_FETCHDATA, SHARED_LOCK, 0));

    ret = 0;
out:
    // XXX necessary? once in the loop, everything goes to the done goto
    if (acall) {
        _ucafs_end_fetch(acall, &tsmall, srv_64bit, code);
        acall = NULL;
    }

    if (areq) {
        afs_DestroyReq(areq);
    }

    if (path) {
        kfree(path);
    }

    crfree(credp);

    return ret;
}
