#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_get: " fmt, ##args)

static int
fetch_read(fetch_context_t * ctx, uint32_t len, uint32_t * bytes_read)
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
fetch_write(fetch_context_t * ctx, uint32_t len, uint32_t * bytes_written)
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

static int
fetchproc(fetch_context_t * ctx, struct dcache * tdc, afs_int32 * transferred)
{
    int ret, len, pos = 0, nbytes, size = tdc->f.chunkBytes;
    struct osi_file * tfile = afs_CFileOpen(&tdc->f.inode);
    if (unlikely(tfile == NULL)) {
	ERROR("opening tdc failed: chunk = %d\n", tdc->f.chunk);
	return -1;
    }

    while (size > 0) {
	len = MIN(ctx->buflen, size);

	/* read from the server */
	if (fetch_read(ctx, len, &nbytes)) {
	    goto out;
	}

	/* send for decryption */
	if (fetch_write(ctx, nbytes, nbytes)) {
	    goto out;
	}

	afs_osi_Write(tfile, -1, ctx->buffer, len);

	pos += len;
	size -= len;
    }

    ret = 0;
out:
    osi_UFSClose(tfile);

    *transferred = pos;
    return ret;
}

int
ucafs_fetch(struct vcache * avc)
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
    ctx->id = -1;

    fetch_init_ucafs(ctx);

    ret = AFSX_STATUS_ERROR;
    /* get the offset */
    if (_ucafs_init_fetch(tc, rxconn, avc, base, size, &bytes_left,
                          &ctx->srv_64bit, &ctx->afs_call)) {
        ERROR("talking to fserver failed\n");
        goto out;
    }

    /* lets fetch our fbox */
    if (fetch_setup_fbox(ctx)) {
	ERROR("fbox_setup failed\n");
	goto out;
    }

out1:
    fetch_cleanup(ctx);

out:
    kfree(path);
    if (ctx) {
	kfree(ctx);
    }

    return ret;
}

static int
fetch_init_ucafs(fetch_context_t * ctx)
{
    int ret;
    afs_uint32 len = ctx->avc->f.m.Length;
    ctx->uc_conn = __get_conn();

    ret = AFSX_fetchstore_start(ctx->uc_conn, UCAFS_STORE, ctx->path,
                                DEFAULT_XFER_SIZE, 0, len, &ctx->id,
                                &ctx->fbox_len, &ctx->total_len);

    if (ret == 0) {
        ctx->buflen = DEFAULT_XFER_SIZE;
        ctx->buffer = ALLOC_XFER_BUFFER;
        if (ctx->buffer == NULL) {
            ERROR("allocating buffer failed\n");
            return -1;
        }

        ctx->real_len = len;
    }

    return 0;
}

static int
fetch_setup_fbox(fetch_context_t * ctx)
{
    int ret, len, size, nbytes;
    uc_fbox_t * fbox = NULL;

    // first, lets read the fbox
    if (_ucafs_read_fbox(ctx->acall, ctx->total_len, &fbox)) {
	ERROR("Reading fbox failed");
	goto out;
    }

    ctx->real_len = fbox->file_size;
    len = ctx->fbox_len;

    /* start writing to userspace */
    while (len > 0) {
	size = MIN(ctx->buflen, len);

	if (fetch_read(ctx, size, &nbytes)) {
	    goto out;
	}

	if (fetch_write(ctx, nbytes, &nbytes)) {
	    goto out;
	}

	len -= size;
    }

    ret = 0;
out:
    if (fbox) {
	kfree(fbox);
    }
    return ret;
}
