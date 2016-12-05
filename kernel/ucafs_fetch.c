#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_get: " fmt, ##args)

static int
_fetch_cleanup(fetch_context_t * fetch_ctx,
               struct afs_FetchOutput * tsmall,
               int code)
{
    int ret = 0;
    if (fetch_ctx == NULL) {
	ERROR("Fetch context is NULL\n");
	return -1;
    }

    if (fetch_ctx->id >= 0) {
	AFSX_fetchstore_finish(fetch_ctx->uc_conn, fetch_ctx->id);
	__put_conn(fetch_ctx->uc_conn);
    }

    if (fetch_ctx->buffer) {
	FREE_XFER_BUFFER(fetch_ctx->buffer);
    }

    if (fetch_ctx->afs_call) {
        ret = _ucafs_end_fetch(fetch_ctx->afs_call, tsmall,
                               fetch_ctx->srv_64bit, code);
    }

    return ret;
}

static int
_fetch_parse_fbox(fetch_context_t * fetch_ctx,
                  struct vcache * avc,
                  struct afs_conn * tc,
                  struct rx_connection * rxconn,
                  afs_size_t base,
		  uc_fbox_t ** p_fbox)
{
    int ret = -1, len = avc->f.m.Length, cursor, abytes, srv_64bit,
        size = 0x7fffffff;
    struct afs_FetchOutput output;
    struct rx_call * acall = NULL;
    uc_fbox_t * fbox = *p_fbox;

    /* FIXME: We can't rely on avc->f.m.Length to get the file size.
     * There is a chance this could be rigged */

    /* we are first going to try with the known length */
    cursor = UCAFS_GET_REAL_FILE_SIZE(len);

    if (_ucafs_init_fetch(tc, rxconn, avc, cursor, size, &abytes, &srv_64bit,
                          &acall)) {
        ERROR("initializing with server failed\n");
	goto out;
    }

    /* now, lets parse the fbox information */
    if (_ucafs_read_fbox(acall, abytes, p_fbox)) {
	goto out;
    }

    ERROR("fbox length: %d, file_size: %d\n", fbox->fbox_len, fbox->file_size);
    fetch_ctx->real_len = fbox->file_size;
    fetch_ctx->total_len = fbox->file_size + fbox->fbox_len;
    fetch_ctx->fbox_len = fbox->fbox_len;
    
    ret = 0;
out:
    if (acall) {
	_ucafs_end_fetch(acall, &output, srv_64bit, 0);
    }

    return ret;
}

static int
_fetch_init_ucafs(fetch_context_t * ctx)
{
    int ret;
    afs_uint32 len = ctx->real_len;
    ctx->uc_conn = __get_conn();

    ret = AFSX_fetchstore_start(ctx->uc_conn, UCAFS_FETCH, ctx->path,
                                DEFAULT_XFER_SIZE, 0, len, &ctx->id,
                                &ctx->fbox_len, &ctx->total_len);

    if (ret) {
	ERROR("Initializing uspace failed\n");
	return ret;
    }

    ctx->buflen = DEFAULT_XFER_SIZE;
    ctx->buffer = ALLOC_XFER_BUFFER;
    if (ctx->buffer == NULL) {
	ERROR("allocating buffer failed\n");
	return -1;
    }

    return 0;
}

static int
_fetch_send_fbox(fetch_context_t * fetch_ctx, uc_fbox_t * fbox)
{
    int ret = -1;
    int32_t len = fetch_ctx->fbox_len, size, nbytes;
    struct rx_connection * uc_conn = fetch_ctx->uc_conn;
    struct rx_call * uc_call = NULL;
    uint8_t * buffer = (uint8_t *)fbox;

    while (len > 0) {
	size = MIN(fetch_ctx->buflen, len);
	if ((uc_call = rx_NewCall(uc_conn)) == NULL) {
	    ERROR("store_fbox rx_NewCall returned NULL\n");
	    goto out;
	}

        if (StartAFSX_fetchstore_fbox(uc_call, fetch_ctx->id, UCAFS_FBOX_WRITE,
                                      size)) {
            ERROR("StartAFSX_fbox failed\n");
            goto out;
        }

        if ((nbytes = rx_Write(uc_call, buffer, size)) != size) {
            ERROR("fbox recv error: exp=%d, act=%d\n", size, nbytes);
            goto out;
        }

        EndAFSX_fetchstore_fbox(uc_call);
        rx_EndCall(uc_call, 0);
        uc_call = NULL;

        len -= size;
	buffer += size;
    }

    ret = 0;
out:
    if (uc_call) {
        EndAFSX_fetchstore_fbox(uc_call);
        rx_EndCall(uc_call, 0);
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
    int ret = AFSX_STATUS_NOOP;
    char * path = NULL;
    fetch_context_t * fetch_ctx = NULL;
    uc_fbox_t * fbox = NULL;

    if (!UCAFS_IS_CONNECTED || vType(avc) == VDIR) {
	return ret;
    }

    if (__is_vnode_ignored(avc, &path)) {
	return ret;
    }

    /* create the context */
    fetch_ctx = (fetch_context_t *)kzalloc(sizeof(fetch_context_t), GFP_KERNEL);
    if (fetch_ctx == NULL) {
	ERROR("allocation error on fetch context");
	return AFSX_STATUS_ERROR;
    }

    fetch_ctx->id = -1;
    fetch_ctx->path = path;

    /* 1 - Initialize the userspace RPC call */
    if (_fetch_parse_fbox(fetch_ctx, avc, tc, rxconn, base, &fbox)) {
        ERROR("there was an error in parsing fbox");
	ret = AFSX_STATUS_NOOP;
	goto out;
    }

    /* 2 - Initialize userspace */
    if (_fetch_init_ucafs(fetch_ctx)) {
	goto out;
    }

    /* 3 - Send the filebox */
    if (_fetch_send_fbox(fetch_ctx, fbox)) {
	goto out;
    }

    goto out;

    ret = 0;
out1:
    _fetch_cleanup(fetch_ctx, tsmall, ret);
out:
    kfree(fetch_ctx);
    kfree(path);
    if (fbox) {
	ERROR("fbox_len=%d, file_len=%d\n", fbox->fbox_len, fbox->file_size);
	kfree(fbox);
    }
    return ret;
}
