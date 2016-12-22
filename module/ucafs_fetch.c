#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_fetch: " fmt, ##args)

static int
ucafs_fetch_daemon_init(fetch_context_t * context, int start, int size);

static int
ucafs_fetch_fserv_init(struct afs_conn * tc,
                       struct rx_connection * rxconn,
                       struct vcache * avc,
                       afs_offs_t base,
                       afs_uint32 size,
                       afs_int32 * alength,
                       int * srv_64bit,
                       struct rx_call ** afs_call);

static int
ucafs_fetch_daemon_finish(fetch_context_t * context)
{
    caddr_t buf_ptr;
    XDR xdrs;
    reply_data_t * reply = NULL;
    int ret = -1;

    if (context->id == -1) {
        goto next_op;
    }

    /* lets close the userspace context  */
    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto next_op;
    }

    buflen = READPTR_BUFLEN();

    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);
    if (!xdr_int(&xdrs, &context->id)) {
        ERROR("store_close: could not parse response\n");
        goto next_op;
    }

    ret = ucafs_mod_send1(UCAFS_MSG_FETCH, UCAFS_SUBMSG_FINISH, context->buffer,
                          &xdrs, &reply, &code);
    if (ret) {
        ERROR("store_close, could not get response from uspace\n");
        goto next_op;
    }

next_op:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

int
ucafs_fetch_read(fetch_context_t * context, int tlen, int * byteswritten)
{
    int ret = 0;
    struct rx_call * afs_call = context->afs_call;
    uint8_t * buf = context->buffer;
    afs_int32 nbytes, bytes_left = tlen, size;
    *byteswritten = 0;

    /* send the data to the server */
    RX_AFS_GUNLOCK();
    while (bytes_left > 0) {
        size = MIN(MAX_FSERV_SIZE, bytes_left);

        if ((nbytes = rx_Read(afs_call, buf, size)) != size) {
            ERROR("afs_server exp=%d, act=%d\n", tlen, (int)nbytes);
            ret = -1;
            goto out;
        }

        buf += size;
        bytes_left -= size;
        *byteswritten += size;
    }
    RX_AFS_GLOCK();

out:
    return ret;
}

int
ucafs_fetch(struct afs_conn * tc,
            struct rx_connection * rxconn,
            struct osi_file * fp,
            afs_size_t base,
            struct dcache * adc,
            struct vcache * avc,
            afs_int32 size,
            struct afs_FetchOutput * tsmall)
{
    int ret, start_pos, end_pos, bytes_left, len, written, tdc_end;
    size_t buflen;
    XDR xdrs;
    char * path;
    fetch_context_t * context;

    if (UCAFS_IS_OFFLINE || vType(avc) == VDIR) {
        return UC_STATUS_NOOP;
    }

    if (ucafs_vnode_path(avc, &path)) {
        return UC_STATUS_NOOP;
    }

    /* create the context */
    context = (fetch_context_t *)kzalloc(sizeof(fetch_context_t), GFP_KERNEL);
    if (context == NULL) {
        ERROR("allocation error on fetch context\n");
        kfree(path);
        return AFSX_STATUS_ERROR;
    }

    if ((context->buffer = UCXFER_ALLOC()) == NULL) {
        ERROR("context's buffer allocation failed\n");
        goto out;
    }

    context->buflen = UCXFER_BUFFER_SIZE;
    context->id = -1;
    context->path = path;
    context->avc = avc;
    context->tc = tc;
    context->rx_conn = rxconn;
    context->total_size = avc->f.m.Length;

    start_pos = UCAFS_CHUNK_BASE(base);
    end_pos = MIN(context->total_size, start_pos + MAX(UCAFS_CHUNK_SIZE, size));
    len = end_pos - start_pos;
    tdc_end = base + size;

    ret = ucafs_fetch_fserv_init(tc, rxconn, avc, start_pos, len, &bytes_left,
                                 &context->srv_64bit, &context->afs_call);
    if (ret) {
        ERROR("could not start fileserver. code=%d\n", ret);
        goto out;
    }

    /* instantiate the user space */
    if ((ret = ucafs_fetch_daemon_init(context, start_pos, bytes_left))) {
        ERROR("could not start daemon\n");
        goto out;
    }

    while (bytes_left > 0) {
        if ((buf_ptr = READPTR_LOCK()) == 0) {
            goto out;
        }

        buflen = READPTR_BUFLEN();
        len = MIN(bytes_left, buflen);

        /* create our xdrs and fake the pointers */
        xdrmem_create(&xdrs, buf_ptr, len, XDR_ENCODE);
        afs_osi_Read(fp, -1, xdrs.x_private, len);
        xdrs.x_private += len;

        /* now send the whole thing */
        if (ucafs_fetch_read(context, len, &written)) {
            goto out;
        }

        /* send the enchilada */
        ret = ucafs_mod_send1(UCAFS_MSG_STORE, UCAFS_SUBMSG_PROCESS,
                              context->buffer, &xdrs, &reply, &code);
        if (ret || code) {
            goto out;
        }

        kfree(reply);
        reply = NULL;

        pos += len;
        bytes_left -= len;

        if (pos >= base || pos <= tdc_end) {
            afs_osi_Write(fp, -1, context->buffer, written);
            adc->validPos = pos;
            afs_osi_Wakeup(&adc->validPos);
        }
    }

    ret = 0;
out:
    if (context->afs_call) {
        ucafs_fetch_fserv_close(context->afs_call, small, context->srv_64bit,
                                ret);
    }

    if (reply) {
        kfree(reply);
    }

    kfree(path);

    if (context->buffer) {
        UCXFER_FREE(context->buffer);
    }

    kfree(context);

    return ret;
}

static int
ucafs_fetch_daemon_init(fetch_context_t * context, int start, int size)
{
    int ret = -1, tlen = context->total_len, code;
    XDR xdrs;
    caddr_t buf_ptr;
    uc_fetchstore_t * fetchstore;

    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto out;
    }

    buflen = READPTR_BUFLEN();

    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);
    xdrs.x_private += sizeof(uc_fetchstore_t);
    /* lets start writing, we have to manully move the xdr */
    fetchstore = (uc_fetchstore_t *)buf_ptr;
    *fetchstore = (uc_fetchstore_t){.op = UCAFS_FETCH,
                                    .xfer_size = buflen,
                                    .offset = start,
                                    .part_size = size,
                                    .file_size = context->total_size};
    ret = ucafs_mod_send1(UCAFS_MSG_FETCH, UCAFS_SUBMSG_BEGIN, context->buffer,
                          &xdrs, &reply, &code);
    if (ret || code) {
        ERROR("initializing store for %s (%d, %d)\n", path, pos_start, pos_end);
        goto out;
    }

    // read the response
    x_data = &reply->xdrs;
    if (!xdr_int(x_data, &context->id)) {
        ERROR("could not read response from init stored\n");
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int
ucafs_fetch_fserv_init(struct afs_conn * tc,
                       struct rx_connection * rxconn,
                       struct vcache * avc,
                       afs_offs_t base,
                       afs_uint32 size,
                       afs_int32 * alength,
                       int * srv_64bit,
                       struct rx_call ** afs_call)
{
    int code = 0, code1 = 0;
#ifdef AFS_64BIT_CLIENT
    afs_uint32 length_hi = 0;
#endif
    afs_uint32 length = 0, bytes;
    struct rx_call * call;

    *srv_64bit = 0;

    RX_AFS_GUNLOCK();
    call = rx_NewCall(rxconn);
    RX_AFS_GLOCK();
    if (call) {
#ifdef AFS_64BIT_CLIENT
        afs_size_t length64; /* as returned from server */
        if (!afs_serverHasNo64Bit(tc)) {
            afs_uint64 llbytes = size;
            *srv_64bit = 1;
            RX_AFS_GUNLOCK();
            code = StartRXAFS_FetchData64(
                call, (struct AFSFid *)&avc->f.fid.Fid, base, llbytes);
            if (code != 0) {
                RX_AFS_GLOCK();
                afs_Trace2(afs_iclSetp, CM_TRACE_FETCH64CODE, ICL_TYPE_POINTER,
                           avc, ICL_TYPE_INT32, code);
            } else {
                bytes = rx_Read(call, (char *)&length_hi, sizeof(afs_int32));
                RX_AFS_GLOCK();
                if (bytes == sizeof(afs_int32)) {
                    length_hi = ntohl(length_hi);
                } else {
                    code = rx_Error(call);
                    RX_AFS_GUNLOCK();
                    code1 = rx_EndCall(call, code);
                    RX_AFS_GLOCK();
                    call = NULL;
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
                if (!call)
                    call = rx_NewCall(rxconn);
                code = StartRXAFS_FetchData(
                    call, (struct AFSFid *)&avc->f.fid.Fid, pos, size);
                RX_AFS_GLOCK();
            }
            afs_serverSetNo64Bit(tc);
        }
        if (!code) {
            RX_AFS_GUNLOCK();
            bytes = rx_Read(call, (char *)&length, sizeof(afs_int32));
            RX_AFS_GLOCK();
            if (bytes == sizeof(afs_int32))
                length = ntohl(length);
            else {
                RX_AFS_GUNLOCK();
                code = rx_Error(call);
                code1 = rx_EndCall(call, code);
                call = NULL;
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
                code = rx_EndCall(call, RX_PROTOCOL_ERROR);
                call = NULL;
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

        afs_Trace3(afs_iclSetp, CM_TRACE_FETCH64LENG, ICL_TYPE_POINTER, avc,
                   ICL_TYPE_INT32, code, ICL_TYPE_OFFSET,
                   ICL_HANDLE_OFFSET(length64));
        if (!code)
            *alength = length;
#else  /* AFS_64BIT_CLIENT */
        RX_AFS_GUNLOCK();
        code = StartRXAFS_FetchData(call, (struct AFSFid *)&avc->f.fid.Fid,
                                    base, size);
        RX_AFS_GLOCK();
        if (code == 0) {
            RX_AFS_GUNLOCK();
            bytes = rx_Read(call, (char *)&length, sizeof(afs_int32));
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
                code = rx_Error(call);
                code1 = rx_EndCall(call, code);
                call = NULL;
            }
        }
#endif /* AFS_64BIT_CLIENT */
    } else
        code = -1;

    /* We need to cast here, in order to avoid issues if *alength is
     * negative. Some, older, fileservers can return a negative length,
     * which the rest of the code deals correctly with. */
    if (code == 0 && *alength > (afs_int32)size) {
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
        code = rx_Error(call);
        RX_AFS_GUNLOCK();
        code1 = rx_EndCall(call, code);
        RX_AFS_GLOCK();
        call = NULL;
        code = EIO;
    }

    if (!code && code1)
        code = code1;

    *afs_call = call;

    return code;
}

static int
ucafs_fetch_fserv_close(struct rx_call * afs_call,
                        struct afs_FetchOutput * o,
                        int srv_64bit,
                        int error)
{
    int code;
#ifdef AFS_64BIT_CLIENT
    if (srv_64bit)
        code = EndRXAFS_FetchData64(afs_call, &o->OutStatus, &o->CallBack,
                                    &o->tsync);
    else
        code = EndRXAFS_FetchData(afs_call, &o->OutStatus, &o->CallBack,
                                  &o->tsync);
#else
    code = EndRXAFS_FetchData(afs_call, &o->OutStatus, &o->CallBack, &o->tsync);
#endif
    code = rx_EndCall(afs_call, code | error);

    return code;
}
