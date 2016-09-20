#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_store: " fmt, ##args)

static int store_read(ucafs_ctx_t * ctx, struct osi_file * tfile,
                      afs_uint32 offset, afs_uint32 size,
                      afs_uint32 * bytesread)
{
    struct rx_call * uspace_call;
    afs_int32 nbytes;
    int ret = -1, moredata;
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;

    uspace_call = rx_NewCall(conn);

    if (StartAFSX_readwrite_data(uspace_call, ctx->id, size)) {
        ERROR("StartAFSX_upload_file failed");
        goto out;
    }

    if ((nbytes = rx_Write(uspace_call, ctx->buffer, size)) != size) {
        ERROR("send error: exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    if ((nbytes = rx_Read(uspace_call, ctx->buffer, size)) != size) {
        ERROR("recv error: exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    *bytesread = nbytes;

    ret = 0;
out:
    EndAFSX_readwrite_data(uspace_call, &moredata);
    rx_EndCall(uspace_call, 0);
    return ret;
}

int store_write(ucafs_ctx_t * ctx, afs_uint32 tlen, afs_uint32 * byteswritten)
{
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;
    afs_int32 nbytes;

    *byteswritten = tlen;

    if ((nbytes = rx_Write(ctx->afs_call, ctx->buffer, tlen)) != tlen) {
        ERROR("afs_server send exp=%d, act=%d\n", tlen, (int)nbytes);
        *byteswritten = nbytes;
        return -1;
    }
    return 0;
}

static int store_close(ucafs_ctx_t * ctx, struct AFSFetchStatus * OutStatus,
                       afs_int32 * doProcessFS)
{
    struct AFSVolSync tsync;

    if (ctx->afs_call) {
        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        if (ctx->srv_64bit) {
            EndRXAFS_StoreData64(ctx->afs_call, OutStatus, &tsync);
        } else
#endif
            EndRXAFS_StoreData(ctx->afs_call, OutStatus, &tsync);
        RX_AFS_GLOCK();
    }

    return 0;
}

static int storeproc(ucafs_ctx_t * ctx, struct dcache * tdc, int * more,
                     afs_int32 * transferred)
{
    int ret = AFSX_STATUS_ERROR, size;
    struct osi_file * tfile;
    afs_uint32 tlen, nbytes, pos = 0;
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;

    size = tdc->f.chunkBytes;

    tfile = afs_CFileOpen(&tdc->f.inode);

    *transferred = 0;

    while (size > 0) {
        tlen = (size > ctx->buflen) ? ctx->buflen : size;

        // XXX check for the read return
        afs_osi_Read(tfile, -1, ctx->buffer, tlen);

        if (store_read(rock, tfile, pos, tlen, &nbytes)) {
            goto out;
        }

        if (store_write(rock, nbytes, &nbytes)) {
            goto out;
        }

        // TODO check for nbytes == tlen

        ctx->off += tlen;
        pos += tlen;
        size -= tlen;
    }

    *transferred = pos;
    ret = 0;
out:
    if (tfile) {
        osi_UFSClose(tfile);
    }
    return ret;
}

int store_init(struct vcache * avc, ucafs_ctx_t * ctx, struct vrequest * areq)
{
    int ret = -1;
    afs_int32 code;
    afs_uint32 real_len = ctx->len;
    struct rx_call * afs_call;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;
    struct AFSStoreStatus instatus;

    instatus.Mask = AFS_SETMODTIME;
    instatus.ClientModTime = avc->f.m.Date;

    tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn);

    RX_AFS_GUNLOCK();
    afs_call = rx_NewCall(tc->id);

    if (afs_call) {
#ifdef AFS_64BIT_CLIENT
        // if the server is rrunning in 64 bits
        if (!afs_serverHasNo64Bit(tc)) {
            ctx->srv_64bit = 1;
            code = StartRXAFS_StoreData64(afs_call,
                                          (struct AFSFid *)&avc->f.fid.Fid,
                                          &instatus, 0, real_len, real_len);
        } else {
            // XXX check for total_len > 2^32 - 1
            code = StartRXAFS_StoreData(afs_call,
                                        (struct AFSFid *)&avc->f.fid.Fid,
                                        &instatus, 0, real_len, real_len);
        }
#else
        code = StartRXAFS_StoreData(afs_call, (struct AFSFid *)&avc->f.fid.Fid,
                                    &instatus, 0, real_len, real_len);
#endif
    } else {
        code = -1;
    }

    RX_AFS_GLOCK();

    if (code) {
        ERROR("issues with call\n");
        goto out;
    }

    // allocate the context buffer
    ctx->buffer = (void *)__get_free_page(GFP_KERNEL);
    if (ctx->buffer == NULL) {
        ERROR("could not allocate buffer\n");
        goto out;
    }

    ctx->buflen = AFSX_PACKET_SIZE;
    ctx->off = 0;
    ctx->afs_call = afs_call;
    ctx->rx_conn = rx_conn;

    ret = 0;
out:

    return ret;
}

int UCAFS_store(struct vcache * avc, struct vrequest * areq)
{
    int ret, hash, index;
    ucafs_ctx_t ctx;
    uint64_t tlen;
    afs_int32 bytes_left;
    afs_uint32 nbytes;
    char * path;
    struct dcache * tdc = NULL;
    struct AFSFetchStatus outstatus;
    struct rx_connection * conn = NULL;

    if (!AFSX_IS_CONNECTED) {
        ERROR("upload: not connected\n");
        return AFSX_STATUS_NOOP;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    // if it's not dirty, ignore
    if (!(avc->f.states & CDirty)) {
        kfree(path);
        return AFSX_STATUS_SUCCESS;
    }

    memset(&ctx, 0, sizeof(ucafs_ctx_t));

    ctx.len = tlen = avc->f.m.Length;

    conn = __get_conn();
    if ((ret = AFSX_readwrite_start(conn, UCAFS_WRITEOP, path, AFSX_PACKET_SIZE,
                                    tlen, &ctx.id))) {
        goto out;
    }

    ret = AFSX_STATUS_ERROR;
    if (store_init(avc, &ctx, areq)) {
        ERROR("error initializing store\n");
        goto out;
    }

    // to avoid pageout when reading files, make sure all the vcache dirty
    // pages are flushed to disk. This also obtains the GLOCK()
    osi_VM_StoreAllSegments(avc);
    ConvertWToSLock(&avc->lock);
    // ObtainWriteLock(&afs_xdcache, 6503);

    hash = DVHash(&avc->f.fid);
    index = afs_dvhashTbl[hash];

    // process every dcache entry in order
    bytes_left = ctx.len;
    while (bytes_left > 0) {
        tdc = afs_FindDCache(avc, ctx.off);
        if (!tdc) {
            ERROR("we failed to failed tdc. byte=%d", ctx.off);
            goto out;
        }

        if (storeproc(&ops, &ctx, tdc, NULL, &nbytes)) {
            goto out;
        }

        // ReleaseReadLock(&tdc->tlock);
        afs_PutDCache(tdc);
        tdc = NULL;
        bytes_left -= nbytes;

        index = afs_dvnextTbl[index];
    }

    if (bytes_left > 0) {
        ERROR("some bytes left=%d\n", bytes_left);
        goto out;
    }

    ops.close(&ctx, &outstatus, NULL);
    avc->f.states &= ~CDirty;
    ret = 0;
out:
    // ReleaseWriteLock(&afs_xdcache);
    if (tdc) {
        // ReleaseReadLock(&tdc->tlock);
        afs_PutDCache(tdc);
    }

    if (ctx.afs_call) {
        rx_EndCall(ctx.afs_call, ret);
        ctx.afs_call = NULL;
    }

    AFSX_readwrite_finish(conn, ctx.id);

    if (ctx.buffer)
        __free_page(ctx.buffer);
    if (path)
        kfree(path);

    __put_conn(conn);
    return ret;
}
