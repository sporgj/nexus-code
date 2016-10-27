#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_get: " fmt, ##args)

static afs_int32
_rxfs_fetchInit(struct afs_conn * tc,
                struct rx_connection * rxconn,
                struct vcache * avc,
                afs_offs_t base,
                afs_uint32 size,
                afs_int32 * alength,
                struct dcache * adc,
                struct osi_file * fP,
                struct rx_call ** afs_call);

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
    afs_int32 bytes_left = 0, pos = base, len, nbytes;
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

    ctx = (ucafs_ctx_t *)kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        ERROR("Could not allocate context\n");
        goto out;
    }

    memset(ctx, 0, sizeof(ucafs_ctx_t));
    ctx->id = -1;

#if 0
    /* if we are getting an updated version of the file, we need to
     * verify it */
    if (ucafs_verify_file(avc)) {
        return AFSX_STATUS_NOOP;
    }
#endif

    /* get the offset */
    if (_rxfs_fetchInit(tc, rxconn, avc, base, size, &bytes_left, adc, fp,
                        &ctx->afs_call)) {
        goto out;
    }

    /* allocate the context */

    conn = __get_conn();
    ctx->file_offset = base;
    ctx->len = bytes_left;

    if (_setup_daemon(conn, ctx, path)) {
        goto out;
    }

    fp->offset = 0;
    ERROR("fetching %s (size=%d, len=%d, offset=%d)\n", path, size,
          bytes_left, base);

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

struct rxfs_fetch {
    struct rx_call * call;
};

static afs_int32
_rxfs_fetchInit(struct afs_conn * tc,
                struct rx_connection * rxconn,
                struct vcache * avc,
                afs_offs_t base,
                afs_uint32 size,
                afs_int32 * alength,
                struct dcache * adc,
                struct osi_file * fP,
                struct rx_call ** afs_call)
{
    struct rxfs_fetch * v;
    int code = 0, code1 = 0;
#ifdef AFS_64BIT_CLIENT
    afs_uint32 length_hi = 0;
#endif
    afs_uint32 length = 0, bytes;

    v = (struct rxfs_fetch *)osi_AllocSmallSpace(sizeof(struct rxfs_fetch));
    if (!v)
        osi_Panic("rxfs_fetchInit: osi_AllocSmallSpace returned NULL\n");
    memset(v, 0, sizeof(struct rxfs_fetch));

    RX_AFS_GUNLOCK();
    v->call = rx_NewCall(rxconn);
    RX_AFS_GLOCK();
    if (v->call) {
#ifdef AFS_64BIT_CLIENT
        afs_size_t length64;     /* as returned from server */
        if (!afs_serverHasNo64Bit(tc)) {
            afs_uint64 llbytes = size;
            RX_AFS_GUNLOCK();
            code = StartRXAFS_FetchData64(v->call,
                    (struct AFSFid *) &avc->f.fid.Fid,
                    base, llbytes);
            if (code != 0) {
                RX_AFS_GLOCK();
                afs_Trace2(afs_iclSetp, CM_TRACE_FETCH64CODE,
                        ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code);
            } else {
                bytes = rx_Read(v->call, (char *)&length_hi, sizeof(afs_int32));
                RX_AFS_GLOCK();
                if (bytes == sizeof(afs_int32)) {
                    length_hi = ntohl(length_hi);
                } else {
                    code = rx_Error(v->call);
                    RX_AFS_GUNLOCK();
                    code1 = rx_EndCall(v->call, code);
                    RX_AFS_GLOCK();
                    v->call = NULL;
                }
            }
        }
        if (code == RXGEN_OPCODE || afs_serverHasNo64Bit(tc)) {
            if (base > 0x7FFFFFFF) {
                code = EFBIG;
            } else {
                afs_uint32 pos;
                pos = base;
                RX_AFS_GUNLOCK();
                if (!v->call)
                    v->call = rx_NewCall(rxconn);
                code =
                    StartRXAFS_FetchData(
                            v->call, (struct AFSFid*)&avc->f.fid.Fid,
                            pos, size);
                RX_AFS_GLOCK();
            }
            afs_serverSetNo64Bit(tc);
        }
        if (!code) {
            RX_AFS_GUNLOCK();
            bytes = rx_Read(v->call, (char *)&length, sizeof(afs_int32));
            RX_AFS_GLOCK();
            if (bytes == sizeof(afs_int32))
                length = ntohl(length);
            else {
                RX_AFS_GUNLOCK();
                code = rx_Error(v->call);
                code1 = rx_EndCall(v->call, code);
                v->call = NULL;
                length = 0;
                RX_AFS_GLOCK();
            }
        }
        FillInt64(length64, length_hi, length);

        if (!code) {
            /* Check if the fileserver said our length is bigger than can fit
             * in a signed 32-bit integer. If it is, we can't handle that, so
             * error out. */
            if (length64 > MAX_AFS_INT32) {
                static int warned;
                if (!warned) {
                    warned = 1;
                    afs_warn("afs: Warning: FetchData64 returned too much data "
                            "(length64 %u.%u); this should not happen! "
                            "Aborting fetch request.\n",
                            length_hi, length);
                }
                RX_AFS_GUNLOCK();
                code = rx_EndCall(v->call, RX_PROTOCOL_ERROR);
                v->call = NULL;
                length = 0;
                RX_AFS_GLOCK();
                code = code != 0 ? code : EIO;
            }
        }

        if (!code) {
            /* Check if the fileserver said our length was negative. If it
             * is, just treat it as a 0 length, since some older fileservers
             * returned negative numbers when they meant to return 0. Note
             * that we must do this in this 64-bit-specific block, since
             * length64 being negative will screw up our conversion to the
             * 32-bit 'alength' below. */
            if (length64 < 0) {
                length_hi = length = 0;
                FillInt64(length64, 0, 0);
            }
        }

        afs_Trace3(afs_iclSetp, CM_TRACE_FETCH64LENG,
                ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code,
                ICL_TYPE_OFFSET,
                ICL_HANDLE_OFFSET(length64));
        if (!code)
            *alength = length;
#else /* AFS_64BIT_CLIENT */
        RX_AFS_GUNLOCK();
        code = StartRXAFS_FetchData(v->call, (struct AFSFid *)&avc->f.fid.Fid,
                base, size);
        RX_AFS_GLOCK();
        if (code == 0) {
            RX_AFS_GUNLOCK();
            bytes =
                rx_Read(v->call, (char *)&length, sizeof(afs_int32));
            RX_AFS_GLOCK();
            if (bytes == sizeof(afs_int32)) {
                *alength = ntohl(length);
                if (*alength < 0) {
                    /* Older fileservers can return a negative length when they
                     * meant to return 0; just assume negative lengths were
                     * meant to be 0 lengths. */
                    *alength = 0;
                }
            } else {
                code = rx_Error(v->call);
                code1 = rx_EndCall(v->call, code);
                v->call = NULL;
            }
        }
#endif /* AFS_64BIT_CLIENT */
    } else
        code = -1;

    /* We need to cast here, in order to avoid issues if *alength is
     * negative. Some, older, fileservers can return a negative length,
     * which the rest of the code deals correctly with. */
    if (code == 0 && *alength > (afs_int32) size) {
        /* The fileserver told us it is going to send more data than we
         * requested. It shouldn't do that, and accepting that much data
         * can make us take up more cache space than we're supposed to,
         * so error. */
        static int warned;
        if (!warned) {
            warned = 1;
            afs_warn("afs: Warning: FetchData64 returned more data than "
                    "requested (requested %ld, got %ld); this should not "
                    "happen! Aborting fetch request.\n",
                    (long)size, (long)*alength);
        }
        code = rx_Error(v->call);
        RX_AFS_GUNLOCK();
        code1 = rx_EndCall(v->call, code);
        RX_AFS_GLOCK();
        v->call = NULL;
        code = EIO;
    }

    if (!code && code1)
        code = code1;

    *afs_call = v->call;

    return 0;
}
