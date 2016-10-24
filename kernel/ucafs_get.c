#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_get: " fmt, ##args)

static int
_read(ucafs_ctx_t * ctx, uint32_t len, uint32_t * bytes_read)
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

static int
_write(ucafs_ctx_t * ctx, uint32_t len, uint32_t * bytes_written)
{
    uint32_t nbytes;
    int ret = -1, moredata = 0;
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
    EndAFSX_readwrite_data(uspace_call, &moredata);
    rx_EndCall(uspace_call, 0);
    return ret;
}

static void
_cleanup(ucafs_ctx_t * ctx, struct afs_FetchOutput * o, int error)
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
    if (ctx->id >= 0) {
        AFSX_readwrite_finish(conn, ctx->id);
    }

    // 3 - Clear up the rest
    if (ctx->buffer) {
        __free_page(ctx->buffer);
    }
    kfree(ctx);
}

static int
_setup_daemon(struct rx_connection * conn, ucafs_ctx_t * ctx, char * path)
{
    int ret;

    ctx->buflen = AFSX_PACKET_SIZE;
    /* 1 -  Connect to the userspace daemon */
    ret = AFSX_readwrite_start(conn, UC_DECRYPT, path, ctx->buflen,
                               ctx->file_offset, ctx->len, &ctx->id);
    if (ret) {
        ERROR("fetchstore start failed: %s\n", path);
        return -1;
    }

    /* 2 - Setup the data structures in the context */
    if ((ctx->buffer = (void *)__get_free_page(GFP_KERNEL)) == NULL) {
        ERROR("could not allocate ctx->buffer\n");
        return -1;
    }

    return 0;
}

static int
_setup_fserv(struct vcache * avc,
             struct afs_conn * tc,
             struct rx_connection * rx_conn,
             int32_t base,
             int32_t tlen,
             ucafs_ctx_t ** pp_ctx)
{
    int ret = -1, code = 0, temp;
    uint32_t nbytes;
    struct rx_call * afs_call = NULL;
    ucafs_ctx_t * ctx = NULL;

    ctx = (ucafs_ctx_t *)kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        ERROR("Could not allocate context\n");
        goto out;
    }
    memset(ctx, 0, sizeof(ucafs_ctx_t));
    ctx->id = -1;

    /* 1 - Connect to the AFS fileserver */
    RX_AFS_GUNLOCK();
    afs_call = rx_NewCall(rx_conn);
    RX_AFS_GLOCK();

#ifdef AFS_64BIT_CLIENT
    if (!afs_serverHasNo64Bit(tc)) {
        ctx->srv_64bit = 1;
        RX_AFS_GUNLOCK();
        code = StartRXAFS_FetchData64(afs_call, &avc->f.fid.Fid, base, tlen);

        if (code == 0) {
            // read the length from the the server
            temp = rx_Read(afs_call, (char *)&nbytes, sizeof(afs_int32));
            RX_AFS_GLOCK();
            if (temp != sizeof(afs_int32)) {
                ERROR("FileServer is sending BS. amt=%d, nbytes=%u\n", temp,
                      ntohl(nbytes));
                code = rx_Error(afs_call);
                RX_AFS_GUNLOCK();
                rx_EndCall(afs_call, code);
                RX_AFS_GLOCK();
                afs_call = NULL;
            }
        } else {
            RX_AFS_GLOCK();
        }
    }

    if (code == RXGEN_OPCODE || afs_serverHasNo64Bit(tc)) {
        RX_AFS_GUNLOCK();
        if (afs_call == NULL) {
            afs_call = rx_NewCall(rx_conn);
        }
        code = StartRXAFS_FetchData(afs_call, &avc->f.fid.Fid, base, tlen);
        RX_AFS_GLOCK();

        ctx->srv_64bit = 0;
        afs_serverSetNo64Bit(tc);
    }
#else
    RX_AFS_GUNLOCK();
    code = StartRXAFS_FetchData(afs_call, &avc->f.fid.Fid, base, tlen);
    RX_AFS_GLOCK();
#endif

    if (code) {
        ERROR("FetchData call failed %d\n", code);
        goto out;
    }

    RX_AFS_GUNLOCK();
    temp = rx_Read(afs_call, (char *)&nbytes, sizeof(afs_int32));
    RX_AFS_GLOCK();
    if (temp != sizeof(afs_int32)) {
        ERROR("BS. amt=%d, nbytes=%u\n", temp, ntohl(nbytes));
        goto out;
    }

    ctx->len = ntohl(nbytes);
    *pp_ctx = ctx;

    ret = 0;
out:
    ctx->afs_call = afs_call;
    return ret;
}

/**
 * Pulls data from the server and decrypts it
 */
int
UCAFS_get(struct afs_conn * tc,
          struct rx_connection * rxconn,
          struct osi_file * fp,
          afs_size_t base,
          struct dcache * adc,
          struct vcache * avc,
          afs_int32 size,
          struct afs_FetchOutput * tsmall)
{
    int ret;
    afs_int32 bytes_left, pos = 0, len, nbytes;
    char * path = NULL;
    ucafs_ctx_t * ctx = NULL;

    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    /* if it's a directory */
    if (avc->f.fid.Fid.Vnode & 1 || vType(avc) == VDIR) {
        return AFSX_STATUS_NOOP;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

#if 0
    /* if we are getting an updated version of the file, we need to
     * verify it */
    if (ucafs_verify_file(avc)) {
        return AFSX_STATUS_NOOP;
    }
#endif

    /* get the offset */
    if (_setup_fserv(avc, tc, rxconn, base, size, &ctx)) {
        goto out;
    }

    conn = __get_conn();
    ctx->file_offset = base;
    if (_setup_daemon(conn, ctx, path)) {
        goto out;
    }

    fp->offset = 0;
    bytes_left = ctx->len;
    /*ERROR("fetching %s (size=%d, len=%d, offset=%d)\n", path, size,
          bytes_left, base);*/

    /* we can now download the file and return to afs_GetDCache */
    while (bytes_left > 0) {
        len = bytes_left > ctx->buflen ? ctx->buflen : bytes_left;

        if (_read(ctx, len, &nbytes)) {
            goto out;
        }

        if (_write(ctx, len, &nbytes)) {
            goto out;
        }

        nbytes = afs_osi_Write(fp, -1, ctx->buffer, nbytes);

        pos += nbytes;
        bytes_left -= nbytes;
    }

    /* adjust the valid position of the adc */
    adc->validPos = pos;

    ret = 0;
out:
    if (path) {
        kfree(path);
    }
    _cleanup(ctx, tsmall, ret);
    return ret;
}
