#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_get: " fmt, ##args)

afs_int32
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
    struct rx_connection * uc_conn;
    struct rx_call * uspace_call;

    // open a session with the daemon
    uc_conn = __get_conn();
    if (uc_conn == NULL) {
        ERROR("__get_conn() returned NULL\n");
        return -1;
    }

    uspace_call = rx_NewCall(uc_conn);

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
    __put_conn(uc_conn);
    EndAFSX_readwrite_data(uspace_call, &moredata);
    rx_EndCall(uspace_call, 0);
    return ret;
}

static void
_cleanup(ucafs_ctx_t * ctx, struct afs_FetchOutput * o, int error)
{
    if (ctx == NULL) {
        return;
    }

    // 1 - End our connection to the fileserver
    _ucafs_end_fetch(ctx->afs_call, o, ctx->srv_64bit, error);

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
ucafs_get(struct afs_conn * tc,
          struct rx_connection * rxconn,
          struct osi_file * fp,
          afs_size_t base,
          struct dcache * adc,
          struct vcache * avc,
          afs_int32 size,
          struct afs_FetchOutput * tsmall)
{
    int ret = AFSX_STATUS_NOOP;
    afs_int32 bytes_left = 0, pos = base, len, nbytes;
    char * path = NULL;
    ucafs_ctx_t * ctx = NULL;

    if (!UCAFS_IS_CONNECTED) {
        return ret;
    }

    /* if it's a directory */
    if (avc->f.fid.Fid.Vnode & 1 || vType(avc) == VDIR) {
        return ret;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return ret;
    }

    /* allocate the context */
    ctx = (ucafs_ctx_t *)kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        ERROR("Could not allocate context\n");
        goto out;
    }

    memset(ctx, 0, sizeof(ucafs_ctx_t));
    ctx->id = -1;

    /* if we are getting an updated version of the file, we need to
     * verify it */
    /*
    if ((ret = ucafs_verify(avc, path))) {
        return ret;
    }
    */

    ret = AFSX_STATUS_ERROR;
    /* get the offset */
    if (_ucafs_init_fetch(tc, rxconn, avc, base, size, &bytes_left,
                          &ctx->srv_64bit, &ctx->afs_call)) {
        ERROR("talking to fserver failed\n");
        goto out;
    }

    conn = __get_conn();
    ctx->file_offset = base;
    ctx->len = bytes_left;

    if (_setup_daemon(conn, ctx, path)) {
        goto out;
    }

    fp->offset = 0;
    /*
    ERROR("fetching %s (size=%d, len=%d, offset=%d)\n", path, size,
          bytes_left, base);
    */
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
