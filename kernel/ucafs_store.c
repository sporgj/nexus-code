#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_store: " fmt, ##args)

static int
store_init_ucafs(store_context_t * ctx);

static int
store_init_fserv(store_context_t * ctx, struct vrequest * areq);

static void
store_cleanup(store_context_t * ctx,
              struct AFSFetchStatus * out,
              struct vrequest * areq,
              int ret);
static int
store_fbox(store_context_t * ctx);

/**
 * Reads from the file on disk, sends over RPC and rereads response
 * inside the buffer
 * @param ctx is the context
 * @param tfile is the file object to read from
 * @param offset is the offset within the file to read
 * @param size is the number of bytes to read
 * @param bytesread will contain the total number of bytes processed
 */
static int
store_read(store_context_t * ctx,
           afs_uint32 size,
           afs_uint32 * bytesread)
{
    struct rx_connection * uc_conn;
    struct rx_call * uspace_call;
    afs_int32 nbytes;
    int ret = -1;

    uc_conn = ctx->uc_conn;

    uspace_call = rx_NewCall(uc_conn);

    /* open a read session */
    if (StartAFSX_fetchstore_data(uspace_call, ctx->id, size)) {
        ERROR("StartAFSX_upload_file failed\n");
        goto out;
    }

    /* send the bytes over */
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, size)) != size) {
        ERROR("send error: exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    /* reread the bytes into the buffer */
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, size)) != size) {
        ERROR("recv error: exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    *bytesread = nbytes;

    ret = 0;
out:
    EndAFSX_fetchstore_data(uspace_call);
    rx_EndCall(uspace_call, ret);
    return ret;
}

/**
 * Writes the data to the afs fileserver
 * @param ctx is the context
 * @param tlen is the amount of data to write
 * @param byteswritten
 * @return 0 on success
 */
static int
store_write(store_context_t * ctx, afs_uint32 tlen, afs_uint32 * byteswritten)
{
    int ret = 0;
    afs_int32 nbytes;
    *byteswritten = 0;

    /* send the data to the server */
    if ((nbytes = rx_Write(ctx->afs_call, ctx->buffer, tlen)) != tlen) {
        ERROR("afs_server exp=%d, act=%d\n", tlen, (int)nbytes);
        ret = -1;
    }

    *byteswritten = nbytes;
    return ret;
}

static int
storeproc(store_context_t * ctx, struct dcache * tdc, afs_int32 * transferred)
{
    int ret = AFSX_STATUS_ERROR;
    afs_uint32 tlen, nbytes, pos = 0;
    afs_int32 size = tdc->f.chunkBytes;
    struct osi_file * tfile = afs_CFileOpen(&tdc->f.inode);

    *transferred = 0;

    while (size > 0) {
        tlen = (size > ctx->buflen) ? ctx->buflen : size;

        // XXX check for the read return
        afs_osi_Read(tfile, -1, ctx->buffer, tlen);

        if (store_read(ctx, tlen, &nbytes)) {
            goto out;
        }

        if (store_write(ctx, nbytes, &nbytes)) {
            goto out;
        }

        /* update the context */
        ctx->off += tlen;
        pos += tlen;
        size -= tlen;
    }

    *transferred = pos;
    ret = 0;
out:
    osi_UFSClose(tfile);
    return ret;
}

int
ucafs_store(struct vcache * avc, struct vrequest * areq, int sync)
{
    int ret, nbytes, chunk_no, bytes_left;
    store_context_t * ctx = NULL;
    struct dcache * tdc;
    char * path = NULL;
    struct AFSFetchStatus out;

    if (!UCAFS_IS_CONNECTED || __is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    // if it's not dirty
    if (!(avc->f.states & CDirty)) {
        kfree(path);
        return AFSX_STATUS_SUCCESS;
    }

    ctx = (store_context_t *)kmalloc(sizeof(store_context_t), GFP_KERNEL);
    if (ctx == NULL) {
        goto out;
    }

    memset(ctx, 0, sizeof(store_context_t));
    ctx->id = -1;
    ctx->avc = avc;
    ctx->path = path;

    ret = AFSX_STATUS_ERROR;

    /* flushes out the dirty pages to disk and acquires the GLOCK */
    osi_VM_StoreAllSegments(avc);
    ConvertWToSLock(&avc->lock);

    /* 1 - Contact our daemon, to start processing the file */
    if (store_init_ucafs(ctx)) {
        goto out1;
    }

    /* 2 - Contact the file server */
    if (store_init_fserv(ctx, areq)) {
        goto out1;
    }

    ret = EIO;
    chunk_no = 0;
    bytes_left = ctx->real_len;
    while (bytes_left > 0) {
        tdc = afs_FindDCache(avc, ctx->off);
        if (!tdc) {
            ERROR("tdc null. path=%s, chunk_no=%d", path, chunk_no);
            goto out;
        }

        // ERROR("tdc. path=%s, chunk_no=%d, offset=%d\n", path, tdc->f.chunk,
        // ctx->off);

        ObtainSharedLock(&tdc->lock, 6504);
        if (storeproc(ctx, tdc, &nbytes)) {
            goto out2;
        }

        /* update the dcache entry */
        ObtainWriteLock(&afs_xdcache, 6660);
        if (afs_indexFlags[tdc->index] & IFDataMod) {
            afs_indexFlags[tdc->index] &= ~IFDataMod;
            afs_stats_cmperf.cacheCurrDirtyChunks--;
            afs_indexFlags[tdc->index] &= ~IFDirtyPages;

            if (sync & AFS_VMSYNC_INVAL) {
                afs_indexFlags[tdc->index] &= ~IFAnyPages;
            }
        }
        ReleaseWriteLock(&afs_xdcache);

        UpgradeSToWLock(&tdc->lock, 6505);
        tdc->f.states &= ~DWriting;
        tdc->dflags |= DFEntryMod;
        ReleaseWriteLock(&tdc->lock);

        bytes_left -= nbytes;
        chunk_no++;

        afs_PutDCache(tdc);
        tdc = NULL;
    }

    /* 3 - Now send the fbox data to the fileserver */
    if (store_fbox(ctx)) {
        ERROR("sending fbox failed");
        goto out1;
    }

    /* TODO: run afs_analyze here to make sure all the packets went through */
    UpgradeSToWLock(&avc->lock, 6506);
    avc->f.states &= ~CDirty;

    ret = 0;
out2:
    /* In case there's an exit in the loop, the tdc's shared lock is still
     * held and needs to be released */
    if (tdc) {
        ReleaseSharedLock(&tdc->lock);
        afs_PutDCache(tdc);
        tdc = NULL;
    }

out1:
    store_cleanup(ctx, &out, areq, ret);

out:
    kfree(path);
    if (ctx) {
        kfree(ctx);
    }

    return ret;
}

/**
 * Saves the fbox into the context
 */
static int
store_fbox(store_context_t * ctx)
{
    int ret = -1;
    int32_t len = ctx->fbox_len, size, nbytes;
    struct rx_connection * uc_conn = ctx->uc_conn;
    struct rx_call * uc_call = NULL;

    while (len > 0) {
        size = MIN(ctx->buflen, len);
        if ((uc_call = rx_NewCall(uc_conn)) == NULL) {
            ERROR("store_fbox rx_NewCall returned NULL\n");
            goto out;
        }

        if (StartAFSX_fetchstore_fbox(uc_call, ctx->id, UCAFS_FBOX_READ,
                                      size)) {
            ERROR("StartAFSX_fbox failed\n");
            goto out;
        }

        if ((nbytes = rx_Read(uc_call, ctx->buffer, size)) != size) {
            ERROR("fbox recv error: exp=%d, act=%d\n", size, nbytes);
            goto out;
        }

        EndAFSX_fetchstore_fbox(uc_call);
        rx_EndCall(uc_call, 0);
        uc_call = NULL;

        if (store_write(ctx, nbytes, &nbytes)) {
            goto out;
        }

        len -= size;
    }

    ret = 0;
out:
    if (uc_call) {
        EndAFSX_fetchstore_fbox(uc_call);
        rx_EndCall(uc_call, 0);
    }
    return ret;
}

/**
 * Sets up the connection with the userspace.
 * @param ctx
 * @return 0 on success.
 */
static int
store_init_ucafs(store_context_t * ctx)
{
    int ret;
    afs_uint32 len = ctx->avc->f.m.Length;
    ctx->uc_conn = __get_conn();

    ret = AFSX_fetchstore_start(ctx->uc_conn, UCAFS_STORE, ctx->path,
                                DEFAULT_XFER_SIZE, 0, len, &ctx->id,
                                &ctx->fbox_len, &ctx->total_len);

    if (ret == 0) {
        /* allocate the required buffer */
        ctx->buflen = DEFAULT_XFER_SIZE;
        ctx->buffer = ALLOC_XFER_BUFFER;
        if (ctx->buffer == NULL) {
            ERROR("allocating buffer failed\n");
            ret = -1;
        }

        ctx->real_len = len;
    }

    return ret;
}

static int
store_init_fserv(store_context_t * ctx, struct vrequest * areq)
{
    int ret = -1, len = ctx->total_len, code;
    struct rx_call * afs_call = NULL;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;
    struct AFSStoreStatus instatus;
    struct vcache * avc = ctx->avc;

    if ((tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn)) == NULL) {
        ERROR("allocating afs_Conn failed\n");
        goto out;
    }

    /* send the request to the fileserver */
    RX_AFS_GUNLOCK();
    afs_call = rx_NewCall(tc->id);
    RX_AFS_GLOCK();

    if (afs_call) {
        /* set the date and time */
        instatus.Mask = AFS_SETMODTIME;
        instatus.ClientModTime = avc->f.m.Date;

        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        // if the server is rrunning in 64 bits
        if (!afs_serverHasNo64Bit(tc)) {
            ctx->srv_64bit = 1;
            code = StartRXAFS_StoreData64(afs_call, &avc->f.fid.Fid, &instatus,
                                          0, len, len);
        } else {
            // XXX check for total_len > 2^32 - 1
            code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus, 0,
                                        len, len);
        }
#else
        code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus, 0,
                                    len, len);
#endif
    } else {
        code = -1;
    }

    RX_AFS_GLOCK();

    if (code) {
        ERROR("starting fileserver transfer FAILED\n");
        goto out;
    }

    ctx->afs_call = afs_call;
    ctx->rx_conn = rx_conn;
    ctx->tc = tc;

    ret = 0;
out:
    return ret;
}

static void
store_cleanup(store_context_t * ctx,
              struct AFSFetchStatus * out,
              struct vrequest * areq,
              int ret)
{
    int code;
    struct AFSVolSync tsync;

    /* free all the pointer stuff in our store context */
    if (ctx->buffer) {
        FREE_XFER_BUFFER(ctx->buffer);
    }

    if (ctx->id != -1) {
        AFSX_fetchstore_finish(ctx->uc_conn, ctx->id);
    }

    if (ctx->uc_conn) {
        __put_conn(ctx->uc_conn);
    }

    /* free everything for our side */
    if (ctx->afs_call) {
        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        if (ctx->srv_64bit)
            code = EndRXAFS_StoreData64(ctx->afs_call, out, &tsync);
        else
#endif
            code = EndRXAFS_StoreData(ctx->afs_call, out, &tsync);
        RX_AFS_GLOCK();
    }

    if (ctx->tc) {
        afs_PutConn(ctx->tc, ctx->rx_conn, 0);
    }

    if (ret == 0) {
        // call doProcessFS here
    }
}
