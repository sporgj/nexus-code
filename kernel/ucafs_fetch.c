#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_fetch: " fmt, ##args)

static int fetch_read(ucafs_ctx_t * ctx, uint32_t len, uint32_t * bytes_read)
{
    uint32_t nbytes;

    if ((nbytes = rx_Read(ctx->afs_call, ctx->buffer, len)) != len) {
        ERROR("reading from afs_server: exp=%u, act=%u\n", len, nbytes);
        *bytes_read = nbytes;
        return -1;
    }

    *bytes_read = nbytes;
    return 0;
}

static int fetch_write(ucafs_ctx_t * ctx, uint32_t len,
                       uint32_t * bytes_written, int * moredata)
{
    uint32_t nbytes;
    int ret = -1;
    struct rx_call * uspace_call;

    // open a session with the daemon
    uspace_call = rx_NewCall(conn);

    // send it to uspace
    if (StartAFSX_readwrite_data(uspace_call, ctx->id, len)) {
        ERROR("StartAFSX_upload_file failed");
        goto out1;
    }

    // copy the bytes over
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, len)) != len) {
        ERROR("send error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    // read back the decrypted stream
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, len)) != len) {
        ERROR("recv error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    *bytes_written = nbytes;

    ret = 0;
out1:
    EndAFSX_readwrite_data(uspace_call, moredata);
    rx_EndCall(uspace_call, 0);
    return ret;
}

static void fetch_cleanup(ucafs_ctx_t * ctx, struct afs_FetchOutput * o,
                          int error)
{
    struct rx_call * afs_call;
    int code;
    if (ctx == NULL) {
        return;
    }

    // 1 - End our connection to the fileserver
    afs_call = ctx->afs_call;

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
    rx_EndCall(afs_call, code | error);

    // 2 - Clean up the connection to ucafs
    if (ctx->id) {
        AFSX_readwrite_finish(conn, ctx->id);
    }

    // 3 - Clear up the rest
    if (ctx->buffer) {
        __free_page(ctx->buffer);
    }
    kfree(ctx);
}

static int init_sgx_socket(ucafs_ctx_t * ctx, char * path)
{
    int ret;
    /* 1 -  Connect to the userspace daemon */
    if ((ret = AFSX_readwrite_start(conn, UCAFS_READOP, path, AFSX_PACKET_SIZE,
                                    ctx->len, &ctx->id, &ctx->padded_len))) {
        if (ret == AFSX_STATUS_ERROR) {
            ERROR("fetchstore start failed: %s\n", path);
            return -1;
        }
    }

    /* 2 - Setup the data structures in the context */
    if ((ctx->buffer = (void *)__get_free_page(GFP_KERNEL)) == NULL) {
        ERROR("could not allocate ctx->buffer\n");
        return -1;
    }

    ctx->buflen = AFSX_PACKET_SIZE;
    return 0;
}

int init_fserv(struct vcache * avc, ucafs_ctx_t ** pp_ctx,
               struct vrequest * areq)
{
    int ret = -1, code, temp;
    uint32_t nbytes, tlen = avc->f.m.Length;
    struct afs_conn * tc;
    struct rx_connection * rx_conn;
    struct rx_call * afs_call;
    ucafs_ctx_t * ctx = NULL;

    ctx = (ucafs_ctx_t *)kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        ERROR("Could not allocate context\n");
        goto out;
    }
    memset(ctx, 0, sizeof(ucafs_ctx_t));

    /* 1 - Connect to the AFS fileserver */
    tc = afs_Conn(&avc->f.fid, areq, SHARED_LOCK, &rx_conn);
    if (!tc) {
        ERROR("Could not allocate afs_conn\n");
        goto out;
    }
    afs_call = rx_NewCall(rx_conn);

#ifdef AFS_64BIT_CLIENT
    if (!afs_serverHasNo64Bit(tc)) {
        ctx->srv_64bit = 1;
        code = StartRXAFS_FetchData64(afs_call, &avc->f.fid.Fid, 0, tlen);
    } else {
        code = StartRXAFS_FetchData(afs_call, &avc->f.fid.Fid, 0, tlen);
    }
#else
    code = StartRXAFS_FetchData(afs_call, &avc->f.fid.Fid, 0, tlen);
#endif

    if (code) {
        ERROR("FetchData call failed %d\n", code);
        goto out;
    }

    // read the length from the the server
    temp = rx_Read32(afs_call, &nbytes);
    if (temp != sizeof(afs_int32)) {
        ERROR("FileServer is sending BS. amt=%d, nbytes=%u\n", temp,
              ntohl(nbytes));
        goto out;
    }

    ctx->afs_call = afs_call;
    ctx->len = tlen;
    *pp_ctx = ctx;

    ret = 0;
out:
    return ret;
}

static int fetch_proc(ucafs_ctx_t * ctx, struct dcache * tdc,
                      uint32_t bytes_left, uint32_t * bytes_done)
{
    int ret = -1, moredata;
    uint32_t tdc_len = AFS_CHUNKTOSIZE(tdc->f.chunk), len, nbytes, max_write,
             pos;
    struct osi_file * tfile = afs_CFileOpen(&tdc->f.inode);

    max_write = bytes_left > tdc_len ? tdc_len : bytes_left;
    pos = 0;

    while (max_write) {
        len = max_write > ctx->buflen ? ctx->buflen : max_write;

        if (fetch_read(ctx, len, &nbytes)) {
            goto out;
        }

        if (fetch_write(ctx, len, &nbytes, &moredata)) {
            goto out;
        }

        // let's write this to our tdc
        nbytes = afs_osi_Write(tfile, pos, ctx->buffer, len);
        ERROR("wrote: %u, len=%u\n", nbytes, len);
        pos += len;
        max_write -= len;
    }

    *bytes_done = pos;

    // let's read upto max_write
    ret = 0;
out:
    osi_UFSClose(tfile);
    return ret;
}

int UCAFS_fetch(struct vcache * avc, struct vrequest * areq)
{
    int ret;
    uint32_t bytes_left, pos = 0, nbytes;
    afs_size_t offset, len;
    char * path;
    struct afs_FetchOutput output;
    ucafs_ctx_t * ctx = NULL;
    struct dcache * tdc = NULL;

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
        kfree(path);
        return AFSX_STATUS_NOOP;
    }

    ret = AFSX_STATUS_ERROR;

    if (init_fserv(avc, &ctx, areq)) {
        goto out;
    }

    if (init_sgx_socket(ctx, path)) {
        goto out;
    }

    bytes_left = avc->f.m.Length;
    ObtainWriteLock(&afs_xdcache, 6505);
    //ObtainWriteLock(&avc->lock, 6507);
    while (bytes_left) {
        ERROR("before lock\n");
        //AFS_GLOCK();
        ERROR("after lock\n");
        tdc = afs_GetDCache(avc, pos, areq, &offset, &len, 2);
        //AFS_GUNLOCK();
        ERROR("after unlock\n");
        if (tdc == NULL) {
            ERROR("tdc is null. pos=%u, bytes_left=%u\n", pos, bytes_left);
            goto out1;
        }

        ObtainWriteLock(&tdc->lock, 6506);
        tdc->f.states |= DWriting;

        if (fetch_proc(ctx, tdc, bytes_left, &nbytes)) {
            goto out1;
        }

        ReleaseWriteLock(&tdc->lock);
        tdc->f.states &= ~DWriting;
        tdc->dflags |= DFEntryMod;
        afs_AdjustSize(tdc, nbytes);
        afs_PutDCache(tdc);
        tdc = NULL;

        pos += nbytes;
        bytes_left -= nbytes;
    }
    avc->f.states |= CDecrypted;
    ret = 0;

out1:
    //ReleaseWriteLock(&avc->lock);
    ReleaseWriteLock(&afs_xdcache);
out:
    if (tdc) {
        ReleaseWriteLock(&tdc->lock);
        afs_PutDCache(tdc);
    }
    fetch_cleanup(ctx, &output, ret);
    kfree(path);
    return ret;
}
