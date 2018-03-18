#include "nexus_kern.h"
#include "nexus_module.h"
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/page-flags.h>

#if 0

static int
nexus_store_exit(struct kern_xfer_context * context,
                 int               error,
                 int             * do_processfs)
{
    struct nx_daemon_rsp * reply   = NULL;
    caddr_t        buf_ptr = NULL;
    XDR            xdrs;

    int code   =  0;
    int buflen =  0;
    int ret    = -1;


    *do_processfs = 0;

    /* lets close the userspace context  */
    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto out;
    }

    buflen = READPTR_BUFLEN();

    /* create the encoded XDR data structure on the buffer */
    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);

    if ((xdr_int(&xdrs, &context->id) == FALSE) ||
	(xdr_int(&xdrs, &error)       == FALSE) ) {
	
        READPTR_UNLOCK();
        NEXUS_ERROR("store_close: could not parse response\n");
        goto out;
    }

    ret = nexus_mod_send(AFS_OP_ENCRYPT_STOP, &xdrs, &reply, &code);
    
    if (ret || code) {
        NEXUS_ERROR("store_close, could not get response from uspace\n");
        goto out;
    }

    *do_processfs = 1;

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

/**
 * Instantiates a new transfer context
 * @param context
 * @param avc is the vnode
 * @param bytes the amount of data being transferred
 * @param the starting position of the transfer (should be at a chunk boundary
 *
 * return 0 on success
 */
static int
nexus_store_init(struct kern_xfer_context * context,
                 struct vcache   * avc,
                 afs_size_t        bytes,
                 int               start_pos)
{
    struct nx_daemon_rsp * reply   = NULL;
    caddr_t                buf_ptr = NULL;
    xfer_req_t             xfer_req;
    xfer_rsp_t             xfer_rsp;
    XDR *                  x_data = NULL;
    XDR                    xdrs;

    int code     = 0;
    int ret      = -1;

    if ((buf_ptr = READPTR_LOCK()) == 0) {
        return -1;
    }

    /* initiate a store operation with the daemon */
    xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);

    xfer_req = (xfer_req_t){.op         = NEXUS_STORE,
                            .xfer_size  = bytes,
                            .offset     = start_pos,
                            .file_size  = avc->f.m.Length};

    if ((xdr_opaque(&xdrs, (caddr_t)&xfer_req, sizeof(xfer_req_t)) == FALSE) ||
        (xdr_string(&xdrs, &context->path, NEXUS_PATH_MAX)         == FALSE) ) {
	
        READPTR_UNLOCK();
        NEXUS_ERROR("could not encode xfer_req XDR object\n");

	goto out;
    }

    ret = nexus_mod_send(AFS_OP_ENCRYPT_START, &xdrs, &reply, &code);
    
    if (ret || code) {
        NEXUS_ERROR("init '%s' (start=%d, len=%d)\n", context->path, start_pos,
              (int)bytes);
        goto out;
    }

    /* 2 - Get the response */
    x_data = &reply->xdrs;
    
    if (!xdr_opaque(x_data, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t))) {
        NEXUS_ERROR("could not parse from init\n");
        goto out;
    }

    if (xfer_rsp.xfer_id == -1) {
        NEXUS_ERROR("store_init '%s' FAILED\n", context->path);
        goto out;
    }

    context->id        = xfer_rsp.xfer_id;
    context->xfer_size = bytes;
    context->offset    = start_pos;

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

/**
 * Writes the content of the buffer to the server
 *
 * @param context
 * @param tlen
 * @param byteswritten will contain the number of bytes sent to the server
 */
static int
nexus_store_write_to_fserver(struct kern_xfer_context * context,
                            uint8_t *                  buffer,
                            int                        tlen,
                            int *                      byteswritten)
{
    struct rx_call * afs_call = context->afs_call;
    uint8_t        * buf      = buffer;

    afs_int32 nbytes     = 0;
    afs_int32 bytes_left = tlen;
    afs_int32 size       = 0;

    int ret = 0;

    *byteswritten = 0;

    /* send the data to the server */
    RX_AFS_GUNLOCK();
    
    while (bytes_left > 0) {
        size = MIN(MAX_FSERV_SIZE, bytes_left);

	nbytes = rx_Write(afs_call, buf, size);
	
        if (nbytes != size) {
            NEXUS_ERROR("afs_server exp=%d, act=%d\n", tlen, (int)nbytes);
            ret = -1;
            goto out;
        }

         buf          += size;
         bytes_left   -= size;
        *byteswritten += size;
    }

out:
    RX_AFS_GLOCK();
    return ret;
}

static int
nexus_store_read_chunk_file(struct osi_file * fp,
                            caddr_t           buf,
                            int               bytes_left,
                            int *             byteswritten)
{
    int       ret    = 0;
    afs_int32 nbytes = 0;
    afs_int32 size   = 0;

    *byteswritten = 0;

    while (bytes_left > 0) {
        // XXX: why only read this much from the file at a time?
        size = MIN(MAX_FSERV_SIZE, bytes_left);

        nbytes = afs_osi_Read(fp, -1, buf, size);

        if (nbytes != size) {
            NEXUS_ERROR("nbytes=%d, size=%d\n", nbytes, size);
            goto out;
        }

        buf           += size;
        bytes_left    -= size;
        *byteswritten += size;
    }

out:
    return ret;
}

static int
nexus_store_xfer(struct kern_xfer_context * context,
		 struct dcache   * tdc,
		 int             * xferred)
{
    int                    ret        = -1;
    int                    bytes_left = tdc->f.chunkBytes;
    int                    nbytes     = 0;
    int                    code       = 0;
    int                    size       = 0;
    struct osi_file *      fp         = NULL;
    struct nx_daemon_rsp * reply      = NULL;
    caddr_t                rpc_ptr    = NULL;
    XDR                    xdrs;

    *xferred = 0;

    /* open the chunk file and start encrypting */
    // note: AFS panics on failure
    fp = afs_CFileOpen(&tdc->f.inode);

    while (bytes_left > 0) {

	size = MIN(bytes_left, context->buflen);

        /* 1 - read the file into the buffer */
        mutex_lock_interruptible(&xfer_buffer_mutex);
        if (nexus_store_read_chunk_file(fp, context->buffer, size, &nbytes)) {
            goto out;
        }

        if ((rpc_ptr = READPTR_LOCK()) == 0) {
            goto out;
        }

        /* 2 - tell uspace we have data */
        xdrmem_create(&xdrs, rpc_ptr, READPTR_BUFLEN(), XDR_ENCODE);

	if ( (xdr_int(&xdrs, &context->id) == FALSE) ||
	     (xdr_int(&xdrs, &size)        == FALSE) ) {

	    READPTR_UNLOCK();
            NEXUS_ERROR("xdr store_xfer failed\n");

	    goto out;
        }

        ret = nexus_mod_send(AFS_OP_ENCRYPT_READY, &xdrs, &reply, &code);

        if (ret || code) {
            NEXUS_ERROR("could not send data to uspace (code=%d)\n", code);
            goto out;
        }

        kfree(reply);
        reply = NULL;

        /* write the encrypted data to the server */
        if (nexus_store_write_to_fserver(context, context->buffer, size, &nbytes)) {
            goto out;
        }

        mutex_unlock(&xfer_buffer_mutex);

        bytes_left -= size;
        *xferred   += size;

        // TODO add special handling for files locked on the server
    }

    ret = 0;
out:
    osi_UFSClose(fp);

    if (reply) {
        kfree(reply);
    }

    if (mutex_is_locked(&xfer_buffer_mutex)) {
        mutex_unlock(&xfer_buffer_mutex);
    }

    return ret;
}

/**
 * Storing the dcaches
 */
int
nexus_kern_store(struct vcache          * avc,
                 struct dcache         ** dclist,
                 afs_size_t               bytes,
                 afs_hyper_t            * anewDV,
                 int                    * doProcessFS,
                 struct AFSFetchStatus  * OutStatus,
                 afs_uint32               nchunks,
                 int                      nomore,
                 struct rx_call         * afs_call,
                 char                   * path,
                 int                      base,
                 struct storeOps        * ops,
                 void                   * rock)
{
    int                      ret          = -1;
    int                      bytes_stored = 0;
    int                      nbytes       = 0;
    int                      i;
    struct kern_xfer_context context;

    memset(&context, 0, sizeof(struct kern_xfer_context));

    context.id         = -1;
    context.path       = path;
    context.total_size = avc->f.m.Length;
    context.afs_call   = afs_call;

    /* 1 - instantiate the context */
    // TODO return special code for a NOOP
    if (nexus_store_init(&context, avc, bytes, base)) {
        goto out;
    }

    /* 2 - set the context buffer */
    context.buflen = dev->xfer_len;
    context.buffer = dev->xfer_buffer;

    /* 3 - lets start uploading stuff */
    for (i = 0; i < nchunks; i++) {
        avc->f.truncPos = AFS_NOTRUNC;

        // TODO add code for afs_wakeup for cases file is locked at the server
        if (nexus_store_xfer(&context, dclist[i], &nbytes)) {
            NEXUS_ERROR("nexus_store_xfer error :(");
            goto out;
        }

        // TODO add code for "small" tdc entries: send a buffer of zeros

        bytes_stored += nbytes;
    }

    if (bytes_stored != bytes) {
        NEXUS_ERROR("incomplete store (%s) stored=%d, size=%d\n", path, bytes_stored,
              (int)bytes);
    }

    // close the connection
    ret = (*ops->close)(rock, OutStatus, doProcessFS);

    /* the processs completed successfully, increment the data version */
    if (*doProcessFS) {
        hadd32(*anewDV, 1);
    }

out:
    nexus_store_exit(&context, ret, doProcessFS);

    if (ops) {
        ret = (*ops->destroy)(&rock, ret);
    }

    return ret;
}

#endif

int
nexus_kern_store(struct vcache          * avc,
                 struct dcache         ** dclist,
                 afs_size_t               bytes,
                 afs_hyper_t            * anewDV,
                 int                    * doProcessFS,
                 struct AFSFetchStatus  * OutStatus,
                 afs_uint32               nchunks,
                 int                      nomore,
                 struct rx_call         * afs_call,
                 char                   * path,
                 int                      base,
                 struct storeOps        * ops,
                 void                   * rock)
{
    return -1;
}
