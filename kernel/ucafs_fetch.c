#include "ucafs_kern.h"

/** called to acquire data from the server if tdc if not on disk */
static int fetch_more(void * rock, afs_int32 * len, afs_uint32 * moredata)
{
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;

    printk(KERN_ERR "getting dcache %d\n", ctx->len);
    struct dcache * tdc = afs_ObtainDCacheForWriting(ctx->avc, ctx->off,
                                                     ctx->len, NULL, 0);
    if (!tdc) {
        printk(KERN_ERR "ucafs_fetch: Error getting tdc (off:%d, len:%d)",
               ctx->off, ctx->len);
        return -1;
    }

    ctx->fp = (struct osi_file *)osi_UFSOpen(&tdc->f.inode);
    *len = AFS_CHUNKTOSIZE(tdc->f.chunk);

    tdc->dflags |= DFFetching;
    ctx->tdc = tdc;

    printk(KERN_ERR "fetch_more: len=%d\n", *len);

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
                       afs_uint32 tlen, afs_uint32 * byteswritten)
{
    int ret = -1;
    afs_int32 nbytes;
    ucafs_ctx_t * ctx = (ucafs_ctx_t *)rock;
    // TODO use lock here
    struct rx_call * uspace_call = rx_NewCall(conn);

    *byteswritten = 0;

    // send it to uspace
    if (StartAFSX_download_data(uspace_call, ctx->dw_id, tlen)) {
        printk(KERN_ERR "StartAFSX_upload_file failed");
        goto out1;
    }

    // copy the bytes over
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, tlen)) != tlen) {
        printk(KERN_ERR "send error: exp=%d, act=%u\n", tlen, nbytes);
        goto out1;
    }

    // read back the decrypted stream
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, tlen)) != tlen) {
        printk(KERN_ERR "recv error: exp=%d, act=%u\n", tlen, nbytes);
        goto out1;
    }
    // XXX check amount of bytes written
    afs_osi_Write(fp, -1, ctx->buffer, tlen);

    *byteswritten = tlen;

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
            ctx->len = total_len; //ntohl(length);
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

    if (avc->f.states & CDecrypted) {
        return AFSX_STATUS_NOOP;
    }

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

    printk(KERN_ERR "ucafs_fetch: dw_id=%d, len=%d\n", context->dw_id, context->len);

    remaining_bytes = context->len;

    ObtainWriteLock(&afs_xdcache, 6505);
    while (remaining_bytes) {
        // Gets the tdc
        if (ops.more(context, &chunk_size, 0)) {
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
