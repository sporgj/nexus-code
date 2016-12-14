#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_fetch: " fmt, ##args)

static int
fetch_read(fetch_context_t * context, uint32_t len, uint32_t * bytes_read)
{
    uint32_t nbytes;
    RX_AFS_GUNLOCK();
    nbytes = rx_Read(context->afs_call, context->buffer, len);
    RX_AFS_GLOCK();
    if (nbytes != len) {
        ERROR("reading from fserver error. exp=%u, act=%u\n", len, nbytes);
        return -1;
    }



    *bytes_read = nbytes;
    return 0;
}

static int
fetch_write(fetch_context_t * context, uint32_t len, uint32_t * bytes_written)
{
    uint32_t nbytes;
    int ret = -1;
    struct rx_connection * uc_conn;
    struct rx_call * uspace_call;

    // open a session with the daemon
    uc_conn = context->uc_conn;
    uspace_call = rx_NewCall(uc_conn);

    // send it to uspace
    if (StartAFSX_fetchstore_data(uspace_call, context->id, len)) {
        ERROR("StartAFSX_upload_file failed");
        goto out1;
    }

    // copy the bytes over
    if ((nbytes = rx_Write(uspace_call, context->buffer, len)) != len) {
        ERROR("send error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    // read back the decrypted stream
    if ((nbytes = rx_Read(uspace_call, context->buffer, len)) != len) {
        ERROR("recv error: exp=%d, act=%u\n", len, nbytes);
        goto out1;
    }

    *bytes_written = nbytes;

    ret = 0;
out1:
    EndAFSX_fetchstore_data(uspace_call);
    rx_EndCall(uspace_call, 0);
    return ret;
}

static int
fetch_init_daemon(fetch_context_t * context, int start, int size)
{
    int ret = -1, tlen = context->total_len, dummy;

    ERROR("start=%d size=%d tlen=%d\n", start, size, tlen);

    ret = AFSX_fetchstore_start(context->uc_conn, UCAFS_FETCH, context->path,
                                DEFAULT_XFER_SIZE, start, size, tlen, 0,
                                &context->id, &dummy);
    if (ret) {
        ERROR("fetchstore_start ret=%d\n", ret);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int
fetch_cleanup(fetch_context_t * context,
              struct afs_FetchOutput * tsmall,
              int code)
{
    int ret = 0;
    if (context == NULL) {
        ERROR("Fetch context is NULL\n");
        return -1;
    }

    if (context->id >= 0) {
        AFSX_fetchstore_finish(context->uc_conn, context->id);
        __put_conn(context->uc_conn);
    }

    if (context->afs_call) {
        ret = _ucafs_end_fetch(context->afs_call, tsmall, context->srv_64bit,
                               code);
    }

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
    int ret = AFSX_STATUS_NOOP, end, start_pos, end_pos, bytes_left, len, pos;
    uint32_t nbytes;
    char * path;
    fetch_context_t * context;

    if (!UCAFS_IS_CONNECTED || vType(avc) == VDIR) {
        return ret;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return ret;
    }

    /* create the context */
    context = (fetch_context_t *)kzalloc(sizeof(fetch_context_t), GFP_KERNEL);
    if (context == NULL) {
        ERROR("allocation error on fetch context\n");
        kfree(path);
        return AFSX_STATUS_ERROR;
    }

    if ((context->buffer = ALLOC_XFER_BUFFER) == NULL) {
        ERROR("context's buffer allocation failed\n");
        goto out;
    }

    context->buflen = DEFAULT_XFER_SIZE;

    context->id = -1;
    context->path = path;
    context->uc_conn = __get_conn();
    context->avc = avc;
    context->tc = tc;
    context->rx_conn = rxconn;
    context->total_len = avc->f.m.Length;

    start_pos = FBOX_CHUNK_BASE(base);
    end_pos = FBOX_CHUNK_BASE(base + size) + UCAFS_CHUNK_SIZE;
    len = end_pos - start_pos;

    /* instantiate with the AFS fileserver */
    ret = _ucafs_init_fetch(tc, rxconn, avc, start_pos, len, &bytes_left,
                            &context->srv_64bit, &context->afs_call);
    if (ret) {
        ERROR("could not start fileserver. code=%d\n", ret);
        goto out;
    }

    /* instantiate with our userspace */
    if ((ret = fetch_init_daemon(context, start_pos, bytes_left))) {
        ERROR("could not start daemon\n");
        goto out;
    }

    ERROR("total length=%d\n", context->total_len);

    /* lets begin the data transfer */
    fp->offset = 0;
    pos = start_pos;
    end = start_pos + AFS_CHUNKTOSIZE(adc->f.chunk);
    adc->validPos = base;
    while (bytes_left > 0) {
        size = MIN(bytes_left, context->buflen);

        if (fetch_read(context, size, &nbytes)) {
            goto out;
        }

        if (fetch_write(context, size, &nbytes)) {
            goto out;
        }

        pos += nbytes;
        bytes_left -= nbytes;
        if (pos >= base && pos < end) {
            afs_osi_Write(fp, -1, context->buffer, nbytes);
            // write to the file
            adc->validPos = pos;
            afs_osi_Wakeup(&adc->validPos);
        }

        break;
    }

    avc->is_ucafs_file = 1;
    ret = 0;
out:
    fetch_cleanup(context, tsmall, ret);
    kfree(path);

    if (context->buffer) {
        FREE_XFER_BUFFER(context->buffer);
    }

    kfree(context);

    return ret;
}
