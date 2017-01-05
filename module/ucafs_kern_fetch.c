#include "ucafs_kern.h"
#include "ucafs_mod.h"
#include <linux/mm.h>

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_fetch: " fmt, ##args)

static int
ucafs_fetch_init(fetch_context_t * context,
                 struct vcache * avc,
                 int offset,
                 int size)
{
    int ret = -1, code;
    XDR xdrs, *x_data;
    caddr_t buf_ptr;
    reply_data_t * reply = NULL;
    xfer_req_t xfer_req;
    xfer_rsp_t xfer_rsp;

    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto out;
    }

    xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);
    xfer_req = (xfer_req_t){.op = UCAFS_FETCH,
                            .xfer_size = size,
                            .offset = offset,
                            .file_size = context->total_size};

    if (!xdr_opaque(&xdrs, (caddr_t)&xfer_req, sizeof(xfer_req_t)) ||
        !xdr_string(&xdrs, (char **)&context->path, UCAFS_PATH_MAX)) {
        READPTR_UNLOCK();
        ERROR("daemon_init xdr encoding failed\n");
        goto out;
    }

    ret = ucafs_mod_send(UCAFS_MSG_XFER_INIT, &xdrs, &reply, &code);
    if (ret || code) {
        ERROR("fetch_init fail for %s (start=%d, size=%d)\n", context->path,
              offset, size);
        goto out;
    }

    // read the response
    x_data = &reply->xdrs;
    if (!xdr_opaque(x_data, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t))) {
        ERROR("could not read response from init stored\n");
        goto out;
    }

    context->id = xfer_rsp.xfer_id;
    context->uaddr = xfer_rsp.uaddr;
    context->xfer_size = size;
    context->offset = offset;
    context->buflen = xfer_rsp.buflen;

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

static int
ucafs_fetch_exit(fetch_context_t * context, int error)
{
    caddr_t buf_ptr;
    size_t buflen;
    XDR xdrs;
    reply_data_t * reply = NULL;
    int ret = -1, code;

    if (context->id == -1) {
        return -1;
    }

    /* lets close the userspace context  */
    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto next_op;
    }

    buflen = READPTR_BUFLEN();

    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);
    if (!xdr_int(&xdrs, &context->id) && !xdr_int(&xdrs, &error)) {
        READPTR_UNLOCK();
        ERROR("could not parse xdr response\n");
        goto next_op;
    }

    ret = ucafs_mod_send(UCAFS_MSG_XFER_EXIT, &xdrs, &reply, &code);
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
ucafs_fetch_read(fetch_context_t * context,
                 caddr_t buf,
                 int bytes_left,
                 int * byteswritten)
{
    int ret = 0;
    struct rx_call * afs_call = context->afs_call;
    afs_int32 nbytes, size;
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

        buf += size;
        bytes_left -= size;
        *byteswritten += size;
    }

out:
    RX_AFS_GLOCK();
    return ret;
}

static int
ucafs_fetch_xfer(fetch_context_t * context,
                 struct dcache * adc,
                 struct osi_file * fp,
                 int pos,
                 int bytes_left,
                 int * xferred)
{
    int ret = -1, nbytes, size, code;
    reply_data_t * reply = NULL;
    XDR xdrs;
    caddr_t buf_ptr;

    *xferred = fp->offset = 0;
    while (bytes_left > 0) {
        size = MIN(bytes_left, context->buflen);

        // read from the server
        if (ucafs_fetch_read(context, context->buffer, size, &nbytes)) {
            goto out;
        }

        if ((buf_ptr = READPTR_LOCK()) == 0) {
            goto out;
        }

        /* tell userspace to encrypt */
        xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);
        if (!xdr_int(&xdrs, &context->id) || !xdr_int(&xdrs, &size)) {
            READPTR_UNLOCK();
            ERROR("xdr fetch_data failed\n");
            goto out;
        }

        ret = ucafs_mod_send(UCAFS_MSG_XFER_RUN, &xdrs, &reply, &code);
        if (ret || code) {
            ERROR("ucafs_xfer code=%d, ret=%d\n", ret, code);
            goto out;
        }

        kfree(reply);
        reply = NULL;

        /* move our pointers and copy the data into the tdc file */
        pos += size;
        bytes_left -= size;
        *xferred += size;

        afs_osi_Write(fp, -1, (void *)context->buffer, nbytes);
        adc->validPos = pos;
        afs_osi_Wakeup(&adc->validPos);
    }

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

int
ucafs_kern_fetch(struct afs_conn * tc,
                 struct rx_connection * rxconn,
                 struct osi_file * fp,
                 afs_size_t base,
                 struct dcache * adc,
                 struct vcache * avc,
                 afs_int32 size,
                 struct rx_call * acall,
                 char * path)
{
    int ret = -1, nbytes;
    struct page * page = NULL;
    fetch_context_t _context, *context = &_context;

    memset(context, 0, sizeof(fetch_context_t));
    context->id = -1;
    context->path = path;
    context->total_size = avc->f.m.Length;
    context->afs_call = acall;

    /* 1 - initialize the context */
    if (ucafs_fetch_init(context, avc, base, size)) {
        goto out;
    }

    if (1) {
        goto out;
    }

    /* 2 - Pin the user pages and start tranferring */
    down_read(&dev->daemon->mm->mmap_sem);
    ret = get_user_pages(dev->daemon, dev->daemon->mm,
                         (unsigned long)context->uaddr, 1, 1, 1, &page, NULL);
    if (ret != 1) {
        up_read(&dev->daemon->mm->mmap_sem);
        ERROR("get_user_pages failed. ret=%d, uaddr=%p\n", ret, context->uaddr);
        goto out;
    }

    context->buffer = kmap(page);
    up_read(&dev->daemon->mm->mmap_sem);

    /* 3 - lets start the transfer */
    if (ucafs_fetch_xfer(context, adc, fp, base, size, &nbytes)) {
        goto out1;
    }

    ret = 0;
out1:
    /* unpin the page and release everything */
    kunmap(page);
    if (!PageReserved(page)) {
        SetPageDirty(page);
        page_cache_release(page);
    }

out:
    ret = ucafs_fetch_exit(context, ret);
    return ret;
}
