#include "ucafs_kern.h"
#include "ucafs_module.h"
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/page-flags.h>

static int
ucafs_store_exit(store_context_t * context,
                 struct AFSFetchStatus * out,
                 int error,
                 int * do_processfs)
{
    int code, buflen, ret = -1;
    caddr_t buf_ptr;
    XDR xdrs;
    reply_data_t * reply = NULL;
    *do_processfs = 0;

    /* lets close the userspace context  */
    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto out;
    }

    buflen = READPTR_BUFLEN();

    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);
    if (!xdr_int(&xdrs, &context->id) || !xdr_int(&xdrs, &error)) {
        READPTR_UNLOCK();
        ERROR("store_close: could not parse response\n");
        goto out;
    }

    ret = ucafs_mod_send(UCAFS_MSG_XFER_EXIT, &xdrs, &reply, &code);
    if (ret || code) {
        ERROR("store_close, could not get response from uspace\n");
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

static int
ucafs_store_init(store_context_t * context,
                 struct vcache * avc,
                 afs_size_t bytes,
                 int start_pos)
{
    int ret = -1, code;
    XDR xdrs, *x_data;
    xfer_req_t xfer_req;
    xfer_rsp_t xfer_rsp;
    reply_data_t * reply = NULL;
    caddr_t buf_ptr;

    /* 1 - Lets send a request to open a new session */
    if ((buf_ptr = READPTR_LOCK()) == 0) {
        return -1;
    }

    xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);
    xfer_req = (xfer_req_t){.op = UCAFS_STORE,
                            .xfer_size = bytes,
                            .offset = start_pos,
                            .file_size = avc->f.m.Length};

    if (!xdr_opaque(&xdrs, (caddr_t)&xfer_req, sizeof(xfer_req_t)) ||
        !xdr_string(&xdrs, &context->path, UCAFS_PATH_MAX)) {
        READPTR_UNLOCK();
        ERROR("could not encode xfer_req XDR object\n");
        goto out;
    }

    ret = ucafs_mod_send(UCAFS_MSG_XFER_INIT, &xdrs, &reply, &code);
    if (ret || code) {
        ERROR("init '%s' (start=%d, len=%d)\n", context->path, start_pos,
              (int)bytes);
        goto out;
    }

    /* 2 - Get the response */
    x_data = &reply->xdrs;
    if (!xdr_opaque(x_data, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t))) {
        ERROR("could not parse from init\n");
        goto out;
    }

    context->id = xfer_rsp.xfer_id;
    context->uaddr = xfer_rsp.uaddr;
    context->xfer_size = bytes;
    context->offset = start_pos;
    context->buflen = xfer_rsp.buflen;

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return ret;
}

static int
ucafs_store_write(store_context_t * context,
                  uint8_t * buffer,
                  int tlen,
                  int * byteswritten)
{
    int ret = 0;
    struct rx_call * afs_call = context->afs_call;
    uint8_t * buf = buffer;
    afs_int32 nbytes, bytes_left = tlen, size;
    *byteswritten = 0;

    /* send the data to the server */
    RX_AFS_GUNLOCK();
    while (bytes_left > 0) {
        size = MIN(MAX_FSERV_SIZE, bytes_left);

        if ((nbytes = rx_Write(afs_call, buf, size)) != size) {
            ERROR("afs_server exp=%d, act=%d\n", tlen, (int)nbytes);
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
ucafs_store_xfer(store_context_t * context, struct dcache * tdc, int * xferred)
{
    int ret = -1, code, nbytes, size, bytes_left = tdc->f.chunkBytes;
    struct osi_file * fp;
    caddr_t rpc_ptr;
    reply_data_t * reply = NULL;
    XDR xdrs;

    *xferred = 0;
    fp = afs_CFileOpen(&tdc->f.inode);

    while (bytes_left > 0) {
        size = MIN(bytes_left, context->buflen);

        /* 1 - read the file into the buffer */
        afs_osi_Read(fp, -1, context->buffer, size);

        if ((rpc_ptr = READPTR_LOCK()) == 0) {
            goto out;
        }
        /* 2 - tell uspace we have data */
        xdrmem_create(&xdrs, rpc_ptr, READPTR_BUFLEN(), XDR_ENCODE);
        if (!xdr_int(&xdrs, &context->id) || !xdr_int(&xdrs, &size)) {
            READPTR_UNLOCK();
            ERROR("xdr store_xfer failed\n");
            goto out;
        }

        ret = ucafs_mod_send(UCAFS_MSG_XFER_RUN, &xdrs, &reply, &code);
        if (ret || code) {
            ERROR("could not send data to uspace (code=%d)\n", code);
            goto out;
        }

        if (ucafs_store_write(context, context->buffer, size, &nbytes)) {
            goto out;
        }

        kfree(reply);
        reply = NULL;

        bytes_left -= size;
        *xferred += size;
    }

    ret = 0;
out:
    osi_UFSClose(fp);

    if (reply) {
        kfree(reply);
    }

    return ret;
}

/**
 * Storing the dcaches
 */
int
ucafs_kern_store(struct vcache * avc,
                 struct dcache ** dclist,
                 afs_size_t bytes,
                 afs_hyper_t * anewDV,
                 int * doProcessFS,
                 struct AFSFetchStatus * OutStatus,
                 afs_uint32 nchunks,
                 int nomore,
                 struct rx_call * afs_call,
                 char * path,
                 int base)
{
    int ret = -1, i, nbytes, bytes_stored = 0;
    struct page * page = NULL;
    fetch_context_t _context, *context = &_context;

    memset(context, 0, sizeof(store_context_t));
    context->id = -1;
    context->path = path;
    context->total_size = avc->f.m.Length;
    context->afs_call = afs_call;

    /* 1 - instantiate the context */
    if (ucafs_store_init(context, avc, bytes, base)) {
        return -1;
    }

    /* 2 - pin the user pages and start the transfer */
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

    /* 3 - lets start uploading stuff */
    for (i = 0; i < nchunks; i++) {
        // TODO add code for afs_wakeup for cases file is locked at the server
        if (ucafs_store_xfer(context, dclist[i], &nbytes)) {
            ERROR("ucafs_store_xfer error :(");
            goto out1;
        }

        // TODO add code for "small" tdc entries: send a buffer of zeros

        bytes_stored += dclist[i]->f.chunkBytes;
    }

    if (bytes_stored != bytes) {
        ERROR("incomplete store (%s) stored=%d, size=%d\n", path, bytes_stored,
              (int)bytes);
    }

    ret = 0;
out1:
    /* unpin the page and release everything */
    kunmap(page);
    if (!PageReserved(page)) {
        // DO we really need to say it's "dirty"?
        SetPageDirty(page);
        page_cache_release(page);
    }

out:
    ucafs_store_exit(context, OutStatus, ret, doProcessFS);

    return ret;
}
