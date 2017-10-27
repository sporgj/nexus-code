#include "nexus_kern.h"
#include "nexus_module.h"
#include <linux/mm.h>

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "nexus_fetch: " fmt, ##args)

static int
nexus_fetch_init(fetch_context_t * context,
                 struct vcache   * avc,
                 int               offset,
                 int               size)
{
    int            ret       = -1;
    int            code      =  0;
    XDR            xdrs;
    XDR          * x_data    = NULL;
    caddr_t        buf_ptr;
    reply_data_t * reply     = NULL;
    xfer_req_t     xfer_req;
    xfer_rsp_t     xfer_rsp;

    buf_ptr = READPTR_LOCK();

    if (buf_ptr == 0) {
        goto out;
    }

    xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);

    xfer_req = (xfer_req_t){.op        = UCAFS_FETCH,
                            .xfer_size = size,
                            .offset    = offset,
                            .file_size = context->total_size};


    if ( (xdr_opaque(&xdrs, (caddr_t)&xfer_req,      sizeof(xfer_req_t)) == FALSE) ||
	 (xdr_string(&xdrs, (char **)&context->path, UCAFS_PATH_MAX)     == FALSE) ) {

        READPTR_UNLOCK();
        ERROR("daemon_init xdr encoding failed\n");

        goto out;
    }

    ret = nexus_mod_send(UCAFS_MSG_XFER_INIT, &xdrs, &reply, &code);

    if (ret || code) {
        ERROR("fetch_init fail for %s (start=%d, size=%d)\n", context->path,
              offset, size);
        goto out;
    }

    // read the response
    x_data = &reply->xdrs;

    if (xdr_opaque(x_data, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t)) == FALSE) {
        ERROR("could not read response from init stored\n");
        goto out;
    }

    if (xfer_rsp.xfer_id == -1) {
        ERROR("fetch_init '%s' FAILED\n", context->path);
        goto out;
    }

    context->id        = xfer_rsp.xfer_id;
    context->xfer_size = size;
    context->offset    = offset;

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

static int
nexus_fetch_exit(fetch_context_t * context,
		 int               error)
{
    XDR            xdrs;
    reply_data_t * reply   = NULL;

    caddr_t        buf_ptr = 0;
    size_t         buflen  = 0;
 
    int            ret     = -1;
    int            code    =  0;

    if (context->id == -1) {
        return -1;
    }

    /* lets close the userspace context  */
    buf_ptr = READPTR_LOCK();

    if (buf_ptr == 0) {
        goto next_op;
    }

    buflen = READPTR_BUFLEN();

    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);
    
    if ((xdr_int(&xdrs, &context->id) == FALSE) &&
	(xdr_int(&xdrs, &error)       == FALSE) ) {

	READPTR_UNLOCK();
        ERROR("could not parse xdr response\n");
        goto next_op;
    }

    ret = nexus_mod_send(UCAFS_MSG_XFER_EXIT, &xdrs, &reply, &code);
    
    if (ret || code) {
        ERROR("could not get response from uspace\n");
        goto next_op;
    }

next_op:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

static int
nexus_fetch_write(struct osi_file * fp,
                  caddr_t           buf,
                  int               bytes_left,
                  int             * byteswritten)
{
    afs_int32 nbytes = 0;
    afs_int32 size   = 0;
    int       ret    = 0;

    *byteswritten = 0;

    while (bytes_left > 0) {
        size = MIN(MAX_FSERV_SIZE, bytes_left);

        nbytes = afs_osi_Write(fp, -1, buf, size);
	
        if (nbytes != size) {
            ERROR("nbytes=%d, size=%d\n", nbytes, size);
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
nexus_fetch_read(fetch_context_t * context,
                 caddr_t           buf,
                 int               bytes_left,
                 int             * byteswritten)
{
    struct rx_call * afs_call = context->afs_call;
    afs_int32        nbytes   = 0;
    afs_int32        size     = 0;
    int              ret      = 0;
    
    *byteswritten = 0;

    /* send the data to the server */
    RX_AFS_GUNLOCK();

    while (bytes_left > 0) {
        size = MIN(MAX_FSERV_SIZE, bytes_left);

        if ((nbytes = rx_Read(afs_call, buf, size)) != size) {
            ERROR("afs_server exp=%d, act=%d\n", size, (int)nbytes);
            ret = -1;
            goto out;
        }

         buf           += size;
         bytes_left    -= size;
        *byteswritten  += size;
    }

out:
    RX_AFS_GLOCK();
    return ret;
}

static int
nexus_fetch_xfer(fetch_context_t * context,
                 struct dcache   * adc,
                 struct osi_file * fp,
                 int               pos,
                 int               bytes_left,
                 int             * xferred)
{
    caddr_t        buf_ptr = NULL;
    reply_data_t * reply   = NULL;
    XDR            xdrs;

    int            nbytes  = 0;
    int            size    = 0;
    int            code    = 0;

    int ret = -1;

    
    *xferred = 0;

    while (bytes_left > 0) {

	size = MIN(bytes_left, context->buflen);

        // read from the server
        // mutex_lock_interruptible(&xfer_buffer_mutex);
        if (nexus_fetch_read(context, context->buffer, size, &nbytes)) {
            goto out;
        }

        if ((buf_ptr = READPTR_LOCK()) == 0) {
            goto out;
        }

        /* tell userspace to encrypt */
        xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);
	
        if ((xdr_int(&xdrs, &context->id) == FALSE) ||
	    (xdr_int(&xdrs, &size)        == FALSE) ) {

            READPTR_UNLOCK();
            ERROR("xdr fetch_data failed\n");

            goto out;
        }

        ret = nexus_mod_send(UCAFS_MSG_XFER_RUN, &xdrs, &reply, &code);
	
        if (ret || code) {
            ERROR("nexus_xfer code=%d, ret=%d\n", ret, code);
            goto out;
        }
        

        kfree(reply);
        reply = NULL;

        /* move our pointers and copy the data into the tdc file */
        if (nexus_fetch_write(fp, context->buffer, size, &nbytes)) {
            goto out;
        }

        // mutex_unlock(&xfer_buffer_mutex);

         pos          += size;
         bytes_left   -= size;
        *xferred      += size;

        adc->validPos = pos;

	afs_osi_Wakeup(&adc->validPos);
    }

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    /*
    if (mutex_is_locked(&xfer_buffer_mutex)) {
        mutex_unlock(&xfer_buffer_mutex);
    }
    */

    return ret;
}

int
nexus_kern_fetch(struct afs_conn      * tc,
                 struct rx_connection * rxconn,
                 struct osi_file      * fp,
                 afs_size_t             base,
                 struct dcache        * adc,
                 struct vcache        * avc,
                 afs_int32              size,
                 struct rx_call       * acall,
                 char                 * path)
{
    fetch_context_t context;

    int nbytes =  0;
    int ret    = -1;
    
    
    memset(&context, 0, sizeof(fetch_context_t));

    context.id         = -1;
    context.path       = path;
    context.total_size = avc->f.m.Length;
    context.afs_call   = acall;

    /* 1 - initialize the context */
    if (nexus_fetch_init(&context, avc, base, size)) {
        goto out;
    }

    if (adc) {
        adc->validPos = base;
    }

    /* 2 - set the context buffer */
    context.buflen = dev->xfer_len;
    context.buffer = dev->xfer_buffer;

    /* 3 - lets start the transfer */
    if (nexus_fetch_xfer(&context, adc, fp, base, size, &nbytes)) {
        goto out;
    }

    ret = 0;

 out:
    nexus_fetch_exit(&context, ret);
    // TODO if the userspace returns an error, erase the tdc contents
    return ret;
}
