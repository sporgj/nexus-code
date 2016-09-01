#include "ucafs_kern.h"

/**
 * TODO
 * Checks if we need to download from network or read from disk
 * @param pos is the position in the file
 * @param network is set to 1 if the fetch needs to from
 */
static int fetch_check(ucafs_ctx_t * ctx, uint32_t pos, int * network)
{
    *network = 1;

    return 0;
}

/**
 * read the bytes from the network and send to the enclav
 */
static int fetch_read(ucafs_ctx_t * ctx, uint32_t len, uint32_t pos,
                      uint32_t * bytesread)
{
    int ret = -1;
    uint32_t nbytes;
    struct rx_call * uspace_call;

    // read the bytes from the network
    if ((nbytes = rx_Read(ctx->afs_call, ctx->buffer, len)) != len) {
        printk(KERN_ERR "ucafs_fetch: receive from server failed"
                        " exp=%d, act=%d\n",
               len, nbytes);
        goto out;
    }

    // open a session with the daemon
    uspace_call = rx_NewCall(conn);

    // send it to uspace
    if (StartAFSX_download_data(uspace_call, ctx->dw_id, len)) {
        printk(KERN_ERR "StartAFSX_upload_file failed");
        goto out1;
    }

    // copy the bytes over
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, len)) != len) {
        printk(KERN_ERR "send error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    // read back the decrypted stream
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, len)) != len) {
        printk(KERN_ERR "recv error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    *bytesread = nbytes;

    ret = 0;
out1:
    EndAFSX_download_data(uspace_call);
    rx_EndCall(uspace_call, 0);
out:
    return ret;
}

static int fetch_write(ucafs_ctx_t * ctx, struct osi_file * fp, uint32_t pos,
                       uint32_t len)
{
    // TODO check the return
    afs_osi_Write(fp, pos, ctx->buffer, len);

    return 0;
}

static int fetch_init(ucafs_ctx_t ** context, struct vcache * avc, char * path,
                      struct afs_conn * tc, struct rx_connection * rx_conn)
{
    afs_int32 length, code, bytes, total_len;
    ucafs_ctx_t * ctx = kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        printk(KERN_ERR "fetch_init: could not allocate ctx\n");
        return -1;
    }
    ctx->rx_conn = rx_conn;

    RX_AFS_GUNLOCK();
    ctx->afs_call = rx_NewCall(tc->id);
    RX_AFS_GLOCK();

    ctx->off = 0;
    ctx->srv_64bit = 0;

    total_len = avc->f.m.Length;

#ifdef AFS_64BIT_CLIENT
    if (!afs_serverHasNo64Bit(tc)) {
        RX_AFS_GUNLOCK();
        ctx->srv_64bit = 1;
        code = StartRXAFS_FetchData64(
            ctx->afs_call, (struct AFSFid *)&avc->f.fid.Fid, 0, total_len);
        RX_AFS_GLOCK();
    } else {
        code = StartRXAFS_FetchData(
            ctx->afs_call, (struct AFSFid *)&avc->f.fid.Fid, 0, total_len);
    }
#else
    RX_AFS_GUNLOCK();
    code = StartRXAFS_FetchData(ctx->afs_call, (struct AFSFid *)&avc->f.fid.Fid,
                                0, total_length);
    RX_AFS_GLOCK();
#endif

    // read the 32 bit length field
    if (!code) {
        RX_AFS_GUNLOCK();
        bytes = rx_Read(ctx->afs_call, (char *)&length, sizeof(afs_int32));
        RX_AFS_GLOCK();

        if (bytes == sizeof(afs_int32)) {
            ctx->len = total_len; // ntohl(length);
        } else {
            // cleanup and return
            RX_AFS_GUNLOCK();
            rx_EndCall(ctx->afs_call, 0);
            ctx->afs_call = NULL;
            kfree(ctx);
            printk(KERN_ERR "fetch_init: Server returning bs\n");
            RX_AFS_GLOCK();
            return -1;
        }
    }

    // TODO allocate programmatically by filesize
    ctx->buffer = (void *)__get_free_page(GFP_KERNEL);
    if (ctx->buffer == NULL) {
        kfree(ctx);
        printk(KERN_ERR "fetch_init: could not allocate context buffer\n");
        return -1;
    }
    ctx->buflen = AFSX_PACKET_SIZE;

    if (AFSX_begin_download(conn, path, AFSX_PACKET_SIZE, ctx->len,
                            &ctx->dw_id)) {
        printk(KERN_ERR "ucafs_fetch: start download failed, %s\n", path);
        return -1;
    }

    *context = ctx;
    return 0;
}

static int fetchproc(struct dcache * tdc, uint32_t len)
{
    int ret = -1;
    struct osi_file * fp = NULL;
    uint32_t max_size = AFS_CHUNKTOSIZE(tdc->f.chunk);
    uint32_t towrite = len;
    if (max_size <= len) {
        // then we can't go past
        towrite = len - max_size;
    }

    while (towrite > 0) {
        size = towrite > ctx->buflen ? ctx->buflen : towrite;

        if (fetch_read(ctx, size, pos, &nbytes)) {
            goto out;
        }

        if (fetch_write(ctx, fp, pos, size)) {
            goto out;
        }

        towrite -= size;
    }

    ret = 0;
out:
    if (fp) {
        osi_UFSClose(fp);
    }
    return ret;
}

/**
 * Retrieves all the blocks of a vcache and decrypts them
 */
int UCAFS_fetch(struct vcache * avc, struct vrequest * areq)
{
    int ret;
    uint32_t tlen, nbytes, bytes_left, pos, max_size, towrite, size;
    struct dcache * tdc = NULL;
    struct osi_file * fp = NULL;

    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (!(avc->f.states & CStatd) || avc->f.states & CDecrypted) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    if (avc->f.fid.Fid.Vnode & 1 || vType(avc) == VDIR) {
        return AFSX_STATUS_NOOP;
    }

    ret = AFSX_STATUS_ERROR;

    bytes_left = tlen = avc->f.m.Length;

    while (bytes_left > 0) {
        // acquire the tdc
        tdc = afs_ObtainDCacheForWriting(avc, pos, bytes_left, areq, 0);

        if (!tdc) {
            error = EIO;
            break;
        }

        if (fetchproc(tdc, bytes_left, &nbytes)) {
            goto out;
        }

        // set the new file size
        afs_AdjustSize(tdc, nbytes);
        osi_UFSClose(fp);
        ReleaseWriteLock(&tdc->lock);
        afs_PutCache(tdc);
        tdc = NULL;
        fp = NULL;

        bytes_left -= towrite;
        pos += size;
    }

    ret = 0;
out:
    return ret;
}

#if 0
/** called to acquire data from the server if tdc if not on disk */
static int fetch_more(void * rock, afs_int32 * len, afs_uint32 * moredata)
{
    struct dcache * tdc;
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;
    afs_size_t _len, _pos;
    *moredata = 0;

    printk(KERN_ERR "getting dcache %d\n", ctx->len);
    tdc = afs_GetDCache(ctx->avc, ctx->off, NULL, &_pos, &_len, 1);
    if (!tdc) {
        printk(KERN_ERR "ucafs_fetch: Error getting tdc (off:%d, len:%d)",
               ctx->off, ctx->len);
        return -1;
    }

    if (!(tdc->dflags & DFFetching)
        && !hsame(ctx->avc->f.m.DataVersion, tdc->f.versionNo)) {
        // just get the data
        // tdc = afs_GetDCache(ctx->avc, ctx->off, NULL, &_pos, &_len, 2);
        *moredata = 1;
    }

    ctx->fp = (struct osi_file *)osi_UFSOpen(&tdc->f.inode);

    tdc->dflags |= DFFetching;
    ctx->tdc = tdc;

    *len = (afs_int32)_len;

    printk(KERN_ERR "fetch_more: len=%d, off=%d, moredata=%d\n", *len, _pos,
           ((int)(*moredata)));

    return 0;
}

static int fetch_read(void * rock, afs_uint32 len, afs_uint32 * bytesread)
{
    int ret = 0;
    afs_int32 nbytes;
    // read it from the server
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;

    if ((nbytes = rx_Read(ctx->afs_call, ctx->buffer, len)) != len) {
        printk(KERN_ERR "ucafs_fetch: receive from server failed"
                        " exp=%d, act=%d\n",
               len, nbytes);
        ret = -1;
    }
    *bytesread = nbytes;

    return ret;
}

static int fetch_write(void * rock, struct osi_file * fp, afs_uint32 offset,
                       afs_uint32 len, afs_uint32 * byteswritten)
{
    int ret = -1;
    afs_int32 nbytes;
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;
    // TODO use lock here
    struct rx_call * uspace_call = rx_NewCall(conn);

    *byteswritten = 0;

    // send it to uspace
    if (StartAFSX_download_data(uspace_call, ctx->dw_id, len)) {
        printk(KERN_ERR "StartAFSX_upload_file failed");
        goto out1;
    }

    // copy the bytes over
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, len)) != len) {
        printk(KERN_ERR "send error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    // read back the decrypted stream
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, len)) != len) {
        printk(KERN_ERR "recv error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }
    // XXX check amount of bytes written
    afs_osi_Write(fp, -1, ctx->buffer, len);

    *byteswritten = len;

    ret = 0;
out1:
    EndAFSX_download_data(uspace_call);
    rx_EndCall(uspace_call, 0);

    return ret;
}

static int fetch_close(void * rock, struct vcache * avc, struct dcache * adc,
                       struct afs_FetchOutput * o)
{
    afs_int32 code;
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;
    struct rx_call * afs_call = ctx->afs_call;

#ifdef AFS_64BIT_CLIENT
    if (ctx->srv_64bit)
        code = EndRXAFS_FetchData64(afs_call, &o->OutStatus, &o->CallBack,
                                    &o->tsync);
    else
        code = EndRXAFS_FetchData(afs_call, &o->OutStatus, &o->CallBack,
                                  &o->tsync);
#else
    code = EndRXAFS_FetchData(afs_call, &o->OutStatus, &o->CallBack, &o->tsync);
#endif
    rx_EndCall(afs_call, 0);

    if (ctx->dw_id) {
        AFSX_end_download(conn, ctx->dw_id);
    }

    return 0;
}

static int fetch_destroy(void ** rock, afs_int32 error)
{
    ucafs_ctx_t * ctx = *((ucafs_ctx_t **)rock);

    if (ctx->buffer) {
        __free_page(ctx->buffer);
    }

    return 0;
}

static struct fetchOps ops = { .more = fetch_more,
                               .read = fetch_read,
                               .write = fetch_write,
                               .close = fetch_close,
                               .destroy = fetch_destroy };

int UCAFS_fetch(struct vcache * avc, struct vrequest * areq)
{
    int ret;
    struct dcache * tdc;
    ucafs_ctx_t * context;
    struct afs_FetchOutput outputs;
    afs_int32 remaining_bytes, size, chunk_size, nbytes;
    char * path;
    struct afs_conn * tc = NULL;
    struct rx_connection * rx_conn;

    /* check that the AVC has everything */
    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (!(avc->f.states & CStatd) || avc->f.states & CDecrypted) {
        return AFSX_STATUS_NOOP;
    }
    printk(KERN_ERR "cstatd: %d, decrypted: %d\n", (avc->f.states & CStatd),
           avc->f.states & CDecrypted);

    if (__is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    if (avc->f.fid.Fid.Vnode & 1 || vType(avc) == VDIR) {
        return AFSX_STATUS_NOOP;
    }

    ret = AFSX_STATUS_ERROR;
    printk(KERN_ERR "fetching: %s\n", path);

    tc = afs_Conn(&avc->f.fid, areq, SHARED_LOCK, &rx_conn);
    if (!tc) {
        printk(KERN_ERR "ucafs_fetch: Could not allocate afs_conn\n");
        goto out;
    }

    if (fetch_init(&context, avc, path, tc, rx_conn)) {
        goto out;
    }

    printk(KERN_ERR "ucafs_fetch: dw_id=%d, len=%d\n", context->dw_id,
           context->len);

    remaining_bytes = context->len;

    ObtainWriteLock(&afs_xdcache, 6505);
    while (remaining_bytes) {
        // Gets the tdc
        if (ops.more(context, &chunk_size, &context->moredata)) {
            goto out1;
        }

        while (chunk_size) {
            size = chunk_size > context->buflen ? context->buflen : chunk_size;
            if (ops.read(context, size, &nbytes)) {
                goto out1;
            }

            if (ops.write(context, context->fp, context->off, size, &nbytes)) {
                goto out1;
            }

            chunk_size -= size;
        }

        // close the file and return the tdc
        osi_UFSClose(context->fp);
        ReleaseWriteLock(&tdc->lock);
        afs_PutDCache(tdc);
        tdc->dflags &= ~DFFetching;
        tdc = NULL;

        remaining_bytes -= chunk_size;
        context->off += chunk_size;
    }
    ReleaseWriteLock(&afs_xdcache);

    ret = 0;
    // we are done decrypting
    avc->f.states |= CDecrypted;
out1:
    ops.close(context, avc, context->tdc, &outputs);
    ops.destroy((void **)&context, 0);

    if (tdc) {
        osi_UFSClose(context->fp);
        ReleaseWriteLock(&tdc->lock);
        afs_PutDCache(tdc);
        tdc->dflags &= ~DFFetching;
        tdc = NULL;
    }

    kfree(path);
    kfree(context);
out:
    if (tc) {
        afs_PutConn(tc, rx_conn, SHARED_LOCK);
    }
    return ret;
}
#endif
