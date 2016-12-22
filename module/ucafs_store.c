#include "ucafs_kern.h"
#include "ucafs_mod.h"

typedef struct dcache_item {
    bool is_dirty;
    int chunk_no;
    int pos;
    int len;
    struct dcache * tdc;
} dcache_item_t;

#define MAX_FSERV_SIZE PAGE_SIZE

static int
store_clean_context(store_context_t * context,
                    struct AFSFetchStatus * out,
                    int error)
{
    int code, buflen, ret;
    struct AFSVolSync tsync;
    caddr_t buf_ptr;
    XDR xdrs;
    reply_data_t * reply = NULL;

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

    ret = ucafs_mod_send1(UCAFS_MSG_STORE, UCAFS_SUBMSG_FINISH, context->buffer,
                          &xdrs, &reply, &code);
    if (ret) {
        ERROR("store_close, could not get response from uspace\n");
        goto next_op;
    }

/* TODO: use the code status to determine if to continue or no */

next_op:
    if (context->afs_call) {
        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        if (context->srv_64bit)
            code = EndRXAFS_StoreData64(context->afs_call, out, &tsync);
        else
#endif
            code = EndRXAFS_StoreData(context->afs_call, out, &tsync);
        code = rx_EndCall(context->afs_call, error);
        RX_AFS_GLOCK();

        if (code == 0 && error) {
            code = error;
        }
    }

    if (reply) {
        kfree(reply);
    }

    context->afs_call = NULL;
    return code | ret;
}

static int
store_write(store_context_t * context,
            uint8_t * buffer,
            afs_uint32 tlen,
            afs_uint32 * byteswritten)
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
    RX_AFS_GLOCK();

out:
    return ret;
}

static int
store_init_fserv(store_context_t * context,
                 int base,
                 int chunk_len,
                 struct vrequest * areq)
{
    int ret = -1, code;
    struct AFSStoreStatus instatus;
    struct vcache * avc = context->avc;
    struct rx_call * afs_call;

    RX_AFS_GUNLOCK();
    afs_call = rx_NewCall(context->tc->id);
    RX_AFS_GLOCK();

    if (afs_call) {
        /* set the date and time */
        instatus.Mask = AFS_SETMODTIME;
        instatus.ClientModTime = avc->f.m.Date;

        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        // if the server is rrunning in 64 bits
        if (!afs_serverHasNo64Bit(context->tc)) {
            context->srv_64bit = 1;
            code = StartRXAFS_StoreData64(afs_call, &avc->f.fid.Fid, &instatus,
                                          base, chunk_len, context->total_size);
        } else {
            // XXX check for total_len > 2^32 - 1
            code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus,
                                        base, chunk_len, context->total_size);
        }
#else
        code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus, base,
                                    chunk_len, context->total_size);
#endif
        RX_AFS_GLOCK();
    } else {
        code = -1;
    }

    if (code) {
        ERROR("starting fileserver transfer FAILED\n");
        goto out;
    }

    context->afs_call = afs_call;

    ret = 0;
out:
    return ret;
}

int
ucafs_storesegment(store_context_t * context,
                   dcache_item_t * dclist,
                   int count,
                   int sum_bytes,
                   struct vrequest * areq,
                   int sync,
                   char * path)
{
    int ret = -1, pos_start, pos_end, bytes_left, i, len, written, code;
    caddr_t buf_ptr;
    XDR xdrs, *x_data;
    uc_fetchstore_t * fetchstore;
    size_t buflen;
    reply_data_t * reply = NULL;
    struct osi_file * fp = NULL;
    struct dcache * tdc;
    struct AFSFetchStatus output;

    pos_start = dclist[0].pos;
    pos_end = pos_start + sum_bytes;

    /* start daemon process here */
    if ((ret = store_init_fserv(context, pos_start, sum_bytes, areq))) {
        ERROR("initializing fserv\n");
        return -1;
    }

    if ((buf_ptr = READPTR_LOCK()) == 0) {
        goto out;
    }

    buflen = READPTR_BUFLEN();

    xdrmem_create(&xdrs, buf_ptr, buflen, XDR_ENCODE);
    xdrs.x_private += sizeof(uc_fetchstore_t);
    /* lets start writing, we have to manully move the xdr */
    fetchstore = (uc_fetchstore_t *)buf_ptr;
    *fetchstore = (uc_fetchstore_t){.op = UCAFS_STORE,
                                    .xfer_size = buflen,
                                    .offset = pos_start,
                                    .file_size = context->total_size,
                                    .xfer_id = 0};
    ret = ucafs_mod_send1(UCAFS_MSG_STORE, UCAFS_SUBMSG_BEGIN, context->buffer,
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

    /* now, lets start pushing the data around */
    bytes_left = sum_bytes;
    for (i = 0; i < count; i++) {
        tdc = dclist[i].tdc;
        fp = afs_CFileOpen(&tdc->f.inode);

        READPTR_LOCK();
        bytes_left = dclist[i].len;
        while (bytes_left > 0) {
            if ((buf_ptr = READPTR_LOCK()) == 0) {
                goto out;
            }

            len = MIN(bytes_left, buflen);

            /* create our xdrs and fake the pointers */
            xdrmem_create(&xdrs, buf_ptr, len, XDR_ENCODE);
            afs_osi_Read(fp, -1, xdrs.x_private, len);
            xdrs.x_private += len;

            /* send the enchilada */
            ret = ucafs_mod_send1(UCAFS_MSG_STORE, UCAFS_SUBMSG_PROCESS,
                                  context->buffer, &xdrs, &reply, &code);
            if (ret || code) {
                goto out;
            }

            /* now send the whole thing */
            if (store_write(context, context->buffer, len, &written)) {
                goto out;
            }

            kfree(reply);
            reply = NULL;

            bytes_left -= len;
        }

        /* update the tdc object */
        if (afs_indexFlags[tdc->index] & IFDataMod) {
            afs_indexFlags[tdc->index] &= ~IFDataMod;
            afs_stats_cmperf.cacheCurrDirtyChunks--;
            afs_indexFlags[tdc->index] &= ~IFDirtyPages;
            if (sync & AFS_VMSYNC_INVAL) {
                afs_indexFlags[tdc->index] &= ~IFAnyPages;
            }

            ObtainWriteLock(&tdc->lock, 628);
            tdc->f.states &= ~DWriting;
            tdc->dflags |= DFEntryMod;
            ReleaseWriteLock(&tdc->lock);
        }

        osi_UFSClose(fp);
        fp = NULL;
    }

    ret = 0;
out:
    if (fp == NULL) {
        osi_UFSClose(fp);
    }

    if (reply) {
        kfree(reply);
    }

    store_clean_context(context, &output, ret);

    READPTR_TRY_UNLOCK();

    return ret;
}

int
ucafs_store(struct vcache * avc, struct vrequest * areq, int sync)
{
    int ret, abyte, afs_chunks, dirty_chunks, count, i, bytes_left, sum_bytes;
    afs_hyper_t old_dv, new_dv;
    size_t tdc_per_part, part_per_tdc;
    struct dcache * tdc;
    dcache_item_t *dclist = NULL, *dcitem;
    store_context_t * context;
    char * path;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;

    if (UCAFS_IS_OFFLINE || ucafs_vnode_path(avc, &path)) {
        return UC_STATUS_NOOP;
    }

    /* lets flush all the data */
    osi_VM_StoreAllSegments(avc);
    if (AFS_IS_DISCONNECTED && !AFS_IN_SYNC) {
        kfree(path);
        return ENETDOWN;
    }

    /* store the old data versions */
    hset(old_dv, avc->f.m.DataVersion);
    hset(new_dv, avc->f.m.DataVersion);

    /* Although we would be storing multiple chunks, they share the same
     * context values. So, we will just create a global context here */
    context = (store_context_t *)kzalloc(sizeof(store_context_t), GFP_KERNEL);
    if (context == NULL) {
        ERROR("could not allocate context\n");
        kfree(path);
        return -1;
    }

    context->buffer = UCXFER_ALLOC();
    if (context->buffer == NULL) {
        ERROR("allocate context buffer\n");
        goto out;
    }

    if ((tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn)) == NULL) {
        ERROR("allocating afs_Conn failed\n");
        goto out;
    }

    context->id = -1;
    context->total_size = avc->f.m.Length;
    context->path = path;
    context->avc = avc;
    context->tc = tc;
    context->rx_conn = rx_conn;

    tdc_per_part = CHUNK_RATIO(UCAFS_CHUNK_LOG, AFS_LOGCHUNK);
    part_per_tdc = CHUNK_RATIO(AFS_LOGCHUNK, UCAFS_CHUNK_LOG);

    dclist = (dcache_item_t *)kzalloc(tdc_per_part * sizeof(dcache_item_t),
                                      AFS_LOGCHUNK);
    if (dclist == NULL) {
        ERROR("allocation failed for dcache items\n");
        goto out;
    }

    dirty_chunks = i = count = abyte = sum_bytes = 0;
    bytes_left = avc->f.m.Length;
    afs_chunks = AFS_CHUNK(bytes_left) + 1;

    ConvertWToSLock(&avc->lock);

    while (afs_chunks > 0) {
        /* get the TDC entry */
        if ((tdc = afs_FindDCache(avc, abyte)) == NULL) {
            ERROR("tdc could not be retrieved\n");
            goto out1;
        }

        dcitem = &dclist[i];

        /* lets check if the tdc entry is dirty */
        ObtainSharedLock(&tdc->lock, 8760);
        if (afs_indexFlags[tdc->index] & IFDataMod) {
            dirty_chunks++;
            dcitem->is_dirty = 1;
        }

        dcitem->len = tdc->f.chunkBytes;
        sum_bytes += dcitem->len;
        ReleaseSharedLock(&tdc->lock);

        dcitem->tdc = tdc;
        dcitem->pos = AFS_CHUNKTOBASE(tdc->f.chunk);
        dcitem->chunk_no = tdc->f.chunk;

        i++;
        count++;

        if (count == tdc_per_part) {
        store_chunk:
            /* clear the list */
            if (dirty_chunks) {
                goto skip_store;
            }

            if (ucafs_storesegment(context, dclist, count, sum_bytes, areq,
                                   sync, path)) {
                ERROR("ucafs_storesegment failed ret = %d", ret);
                goto out1;
            }

        skip_store:
            /* put back all the tdc entries, don't upgrade the version number */
            for (i = 0; i < count; i++) {
                afs_PutDCache(dclist[i].tdc);
            }

            abyte += sum_bytes;
            sum_bytes = count = i = dirty_chunks = 0;
        }

        afs_chunks--;
    }

    if (dirty_chunks) {
        goto store_chunk;
    }

    ret = 0;
out1:
    for (i = 0; i < count; i++) {
        afs_PutDCache(dclist[i].tdc);
    }

out:
    if (tc) {
        afs_PutConn(tc, rx_conn, 0);
    }

    if (dclist) {
        kfree(dclist);
    }

    if (context->buffer) {
        UCXFER_FREE(context->buffer);
    }

    kfree(context);
    kfree(path);

    return ret;
}
