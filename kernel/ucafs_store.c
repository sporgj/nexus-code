#include "ucafs_kern.h"
undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_store: " fmt, ##args)

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
store_read(ucafs_ctx_t * ctx,
           struct osi_file * tfile,
           afs_uint32 offset,
           afs_uint32 size,
           afs_uint32 * bytesread)
{
    struct rx_call * uspace_call;
    afs_int32 nbytes;
    int ret = -1, moredata;

    // XXX check for the read return
    afs_osi_Read(tfile, -1, ctx->buffer, size);

    uspace_call = rx_NewCall(conn);

    /* open a read session */
    if (StartAFSX_readwrite_data(uspace_call, ctx->id, size)) {
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
    EndAFSX_readwrite_data(uspace_call, &moredata);
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
store_write(ucafs_ctx_t * ctx, afs_uint32 tlen, afs_uint32 * byteswritten)
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
storeproc(ucafs_ctx_t * ctx, struct dcache * tdc, afs_int32 * transferred)
{
    int ret = AFSX_STATUS_ERROR;
    afs_uint32 tlen, nbytes, pos = 0;
    afs_int32 size = tdc->f.chunkBytes;
    struct osi_file * tfile = afs_CFileOpen(&tdc->f.inode);

    *transferred = 0;

    while (size > 0) {
        tlen = (size > ctx->buflen) ? ctx->buflen : size;
        if (store_read(ctx, tfile, pos, tlen, &nbytes)) {
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

/**
 * Closes all the opened resources
 * @param ctx is the context
 * @param OutStatus would contain the response from the fileserver
 * @param code determines if to process the filesystem
 * @param areq is the request
 */
static int
store_close(ucafs_ctx_t * ctx,
            struct AFSFetchStatus * status,
            int code,
            struct vrequest * areq)
{
    struct AFSVolSync tsync;
    if (ctx == NULL) {
        return -1;
    }

    if (ctx->afs_call) {
        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        if (ctx->srv_64bit) {
            EndRXAFS_StoreData64(ctx->afs_call, status, &tsync);
        } else
#endif
            EndRXAFS_StoreData(ctx->afs_call, status, &tsync);

        rx_EndCall(ctx->afs_call, code);
        RX_AFS_GLOCK();

        ctx->afs_call = NULL;
    }

    /* if everything is ok, process the request */
    if (code == 0) {
        afs_ProcessFS(ctx->avc, status, areq);
    }

    /* close the request */
    if (ctx->id) {
        AFSX_readwrite_finish(ctx->udp_conn, ctx->id);
    }

    if (ctx->udp_conn) {
        __put_conn(ctx->udp_conn);
    }

    if (ctx->buffer) {
        __free_page(ctx->buffer);
    }

    kfree(ctx);
    return 0;
}

static int
store_init(struct vcache * avc,
           ucafs_ctx_t ** pp_ctx,
           char * path,
           struct vrequest * areq)
{
    int ret = -1;
    afs_int32 code = 0;
    afs_uint32 len = avc->f.m.Length;
    struct rx_call * afs_call;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;
    struct AFSStoreStatus instatus;
    ucafs_ctx_t * ctx = kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);

    if (ctx == NULL) {
        ERROR("Could not allocate context :(\n");
        return -1;
    }
    memset(ctx, 0, sizeof(ucafs_ctx_t));

    /* allocate an afs_Conn */
    if ((tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn)) == NULL) {
        ERROR("Could not allocate afs_Conn");
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
        ERROR("issues with call\n");
        goto out;
    }

    /* start a connection with our client */
    ctx->udp_conn = __get_conn();
    if ((ret = AFSX_readwrite_start(ctx->udp_conn, UCAFS_WRITEOP, path,
                                    AFSX_PACKET_SIZE, len, &ctx->id))) {
        ERROR("Starting connection with uspace failed (ret=%d)\n", ret);
        goto out;
    }

    /* allocate the context buffer */
    ctx->buffer = (void *)__get_free_page(GFP_KERNEL);
    if (ctx->buffer == NULL) {
        ERROR("could not allocate buffer\n");
        goto out;
    }

    ctx->len = len;
    ctx->buflen = AFSX_PACKET_SIZE;
    ctx->off = 0;
    ctx->afs_call = afs_call;
    ctx->rx_conn = rx_conn;
    *pp_ctx = ctx;

    ret = 0;
out:
    return ret;
}

int
UCAFS_store(struct vcache * avc, struct vrequest * areq)
{
    int ret;
    ucafs_ctx_t * ctx = NULL;
    afs_int32 bytes_left;
    afs_uint32 nbytes;
    afs_hyper_t new_dv, old_dv;
    char * path = NULL;
    struct dcache * tdc = NULL;
    struct AFSFetchStatus outstatus;

    if (!AFSX_IS_CONNECTED) {
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

    /* start the session with the fileserver */
    if (store_init(avc, &ctx, path, areq)) {
        ERROR("error initializing store\n");
        goto out;
    }

    ret = AFSX_STATUS_ERROR;

    /* to avoid pageout when reading files, make sure all the vcache dirty
    // pages are flushed to disk. This also obtains the GLOCK() */
    osi_VM_StoreAllSegments(avc);
    
    /* set the data versions */
    hset(old_dv, avc->f.m.DataVersion);
    hset(new_dv, avc->f.m.DataVersion);

    ConvertWToSLock(&avc->lock);

    /* iterate through every dcache entry of the vcache */
    bytes_left = ctx->len;
    while (bytes_left > 0) {
        /* TODO: Store reference to tdc entries. We will need to update
         * their version number to that of the avc */

        if ((tdc = afs_FindDCache(avc, ctx->off)) == NULL) {
            ERROR("we failed to failed tdc. byte=%d", ctx->off);
            goto out;
        }

        if (storeproc(ctx, tdc, &nbytes)) {
            goto out;
        }

        afs_PutDCache(tdc);
        tdc = NULL;

        bytes_left -= nbytes;
    }

    if (bytes_left > 0) {
        ERROR("some bytes left=%d\n", bytes_left);
        goto out;
    }

    avc->f.states &= ~CDirty;
    ret = 0;
out:
    if (tdc) {
        afs_PutDCache(tdc);
    }

    store_close(ctx, &outstatus, ret, areq);

    if (path)
        kfree(path);

    return ret;
}
