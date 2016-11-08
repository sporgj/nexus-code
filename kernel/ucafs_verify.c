#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_verify: " fmt, ##args)

static int
fetch_read(ucafs_ctx_t * ctx, uint32_t len, uint32_t * bytes_read)
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
fetch_write(ucafs_ctx_t * ctx,
            uint32_t len,
            uint32_t * bytes_written,
            int * moredata)
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

static void
fetch_cleanup(ucafs_ctx_t * ctx, struct afs_FetchOutput * o, int error, int * ret)
{
    struct rx_call * afs_call;
    int code;
    if (ctx == NULL) {
        return;
    }

    // 1 - End our connection to the fileserver
    if (ctx->afs_call) {
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
    }

    // 2 - Clean up the connection to ucafs
    *ret = AFSX_readwrite_finish(conn, ctx->id);

    // 3 - Clear up the rest
    if (ctx->buffer) {
        __free_page(ctx->buffer);
    }
    kfree(ctx);
}

static int
init_sgx_socket(struct rx_connection * conn, ucafs_ctx_t * ctx, char * path)
{
    int ret = AFSX_readwrite_start(conn, UC_VERIFY, path, AFSX_PACKET_SIZE, 0,
                                   ctx->len, &ctx->id);
    /* 1 -  Connect to the userspace daemon */
    if (ret == AFSX_STATUS_ERROR) {
        ERROR("fetchstore start failed: %s\n", path);
        return -1;
    }

    /* 2 - Setup the data structures in the context */
    if ((ctx->buffer = (void *)__get_free_page(GFP_KERNEL)) == NULL) {
        ERROR("could not allocate ctx->buffer\n");
        return -1;
    }

    ctx->buflen = AFSX_PACKET_SIZE;
    return 0;
}

int
ucafs_verify(struct vcache * avc, char * path)
{
    int ret, len, moredata, bytes_left;
    uint32_t nbytes;
    struct afs_FetchOutput output;
    ucafs_ctx_t * ctx = NULL;
    struct rx_connection * uc_conn = NULL;
    afs_hyper_t fdv;
    struct vrequest * areq = NULL;
    cred_t * credp;
    struct afs_conn * tc;

    if (hsame(avc->f.m.DataVersion, avc->ucafs_verify_dv)) {
        return 0;
    }

    ret = AFSX_STATUS_ERROR;

    /* initialize the context */
    ctx = (ucafs_ctx_t *)kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        return ret;
    }
    memset(ctx, 0, sizeof(ucafs_ctx_t));
    ctx->id = -1;

    credp = crref();
    if (afs_CreateReq(&areq, credp)) {
        ERROR("could not get request\n");
        goto out;
    }

    tc = afs_Conn(&avc->f.fid, areq, 0, &ctx->rx_conn);
    if (tc == NULL) {
        ERROR("Could not allocate afs_Conn\n");
        goto out;
    }

    /* store the value of the current file version */
    hset(fdv, avc->f.m.DataVersion);

    if (_rxfs_fetchInit(tc, ctx->rx_conn, avc, 0, 0x7fffffff, &ctx->len, NULL,
                NULL, &ctx->afs_call)) {
        ERROR("rx fetchinit failed\n");
        goto out;
    }

    ERROR("Receiving=%d, %p\n", ctx->len, ctx->afs_call);

    uc_conn = __get_conn();
    if (init_sgx_socket(conn, ctx, path)) {
        goto out;
    }

    bytes_left = ctx->len;

    while (bytes_left > 0) {
        len = MIN(ctx->buflen, bytes_left);

        if (fetch_read(ctx, len, &nbytes)) {
            goto out;
        }

        if (fetch_write(ctx, len, &nbytes, &moredata)) {
            goto out;
        }

        bytes_left -= nbytes;
    }

    hset(avc->ucafs_verify_dv, fdv);

    ret = 0;
out:
    afs_DestroyReq(areq);
    crfree(credp);

    if (uc_conn) {
        __put_conn(uc_conn);
    }

    fetch_cleanup(ctx, &output, ret, &ret);
    kfree(path);
    return ret;
}
