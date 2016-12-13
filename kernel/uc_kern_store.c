#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_store: " fmt, ##args)

typedef struct dcache_item {
    bool inuse;
    bool is_dirty;
    int chunk_no;
    int pos;
    int tdc_len;
    int consumed;
    struct dcache * tdc;
} dcache_item_t;

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
                                          base, chunk_len, context->total_len);
        } else {
            // XXX check for total_len > 2^32 - 1
            code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus,
                                        base, chunk_len, context->total_len);
        }
#else
        code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus, base,
                                    chunk_len, context->total_len);
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

static int
store_clean_context(store_context_t * context,
                    struct AFSFetchStatus * out,
                    int error)
{
    int code;
    struct AFSVolSync tsync;

    if (context->id != -1) {
        AFSX_fetchstore_finish(context->uc_conn, context->id);
    }

    context->id = -1;

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

    context->afs_call = NULL;
    return code;
}

static int
store_write(struct rx_call * afs_call,
            char * buffer,
            afs_uint32 tlen,
            afs_uint32 * byteswritten)
{
    int ret = 0;
    afs_int32 nbytes;
    *byteswritten = 0;

    /* send the data to the server */
    RX_AFS_GUNLOCK();
    if ((nbytes = rx_Write(afs_call, buffer, tlen)) != tlen) {
        ERROR("afs_server exp=%d, act=%d\n", tlen, (int)nbytes);
        ret = -1;
    }
    RX_AFS_GLOCK();

    *byteswritten = nbytes;
    return ret;
}

static int
store_read(store_context_t * ctx, afs_uint32 size, afs_uint32 * bytesread)
{
    struct rx_connection * uc_conn;
    struct rx_call * uspace_call;
    afs_int32 nbytes;
    int ret = -1;

    uc_conn = ctx->uc_conn;

    uspace_call = rx_NewCall(uc_conn);

    /* open a read session */
    if (StartAFSX_store_data(uspace_call, ctx->id, size)) {
        ERROR("StartAFSX_upload_file failed\n");
        goto out;
    }

    /* send the bytes over */
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, size)) != size) {
        ERROR("ucafs_send exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    /* reread the bytes into the buffer */
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, size)) != size) {
        ERROR("ucafs_recv exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    *bytesread = nbytes;

    ret = 0;
out:
    EndAFSX_store_data(uspace_call);
    rx_EndCall(uspace_call, ret);
    return ret;
}

static int
ucafs_storetdc(store_context_t * context,
               struct dcache * tdc,
               size_t offset,
               size_t bytes_left,
               size_t * bytes_io)
{
    int ret = -1, size, nbytes, total_bytes = 0;
    struct osi_file * file = afs_CFileOpen(&tdc->f.inode);

    while (bytes_left > 0) {
        size = MIN(bytes_left, context->buflen);

        afs_osi_Read(file, offset, context->buffer, size);

        if (store_read(context, size, &nbytes)) {
            goto out;
        }

        if (store_write(context->afs_call, context->buffer, nbytes, &nbytes)) {
            goto out;
        }

        total_bytes += size;
        offset += size;
        bytes_left -= size;
    }

    *bytes_io = total_bytes;
    ret = 0;
out:
    osi_UFSClose(file);
    return ret;
}

static int
ucafs_storesegment(store_context_t * context,
                   dcache_item_t * dclist,
                   int first,
                   int len,
                   struct vcache * avc,
                   struct vrequest * areq,
                   int sync,
                   char * path,
                   afs_hyper_t * new_dv,
                   size_t * total_bytes,
                   size_t * tdc_seen)
{
    int ret = -1, j, tdc_start, tdc_end, pos_start, pos_end, curr, is_dirty,
        flen, tlen, tdc_count, tdc_left, size, chunk_len;
    size_t nbytes;
    struct dcache_item * d_item;
    struct dcache * tdc;
    struct AFSFetchStatus output;

#define INTERVALS_OVERLAP(x1, x2, a1, a2)                                      \
    ((x1 >= a1 && x1 < a2) || (x2 >= a1 && x2 < a2))

    /* get the index of the first element */
    pos_start = dclist[first].pos + dclist[first].consumed;
    flen = avc->f.m.Length;
    chunk_len = MIN(UCAFS_CHUNK_SIZE, flen - pos_start);
    pos_end = pos_start + chunk_len;

    /* loop through the tdc entries and see if there's anyone to save to disk */
    is_dirty = 0;
    curr = first;
    for (j = 0; j < len; j++) {
        d_item = &dclist[curr];
        tdc_start = d_item->pos;
        tdc_end = tdc_start + d_item->tdc_len;

        /* check if we can start storing */
        if (INTERVALS_OVERLAP(tdc_start, tdc_end, pos_start, pos_end)) {
            if (d_item->is_dirty) {
                is_dirty = 1;
                break;
            }
        } else {
            // we are out of range, lets leave
            break;
        }

        curr = (curr + 1) % len;
    }

    /* now, if we have any saved tdc entries, lets save it */
    if (is_dirty) {
        ret = AFSX_fetchstore_start(
            context->uc_conn, UCAFS_STORE, context->path, DEFAULT_XFER_SIZE,
            pos_start, chunk_len, flen, 0, &context->id, &context->fbox_len);
        if (ret) {
            ERROR("initializing daemon failed ret=%d\n", ret);
            goto out;
        }

        context->total_len = tlen = flen + context->fbox_len;

        ret = store_init_fserv(context, pos_start, chunk_len, areq);
        if (ret) {
            ERROR("fserv_init failed\n");
            goto out;
        }
    }

    /* iterate through the cache entries and start saving them */
    curr = first;
    tdc_count = 0;
    for (j = 0; j < len; j++) {
        d_item = &dclist[curr];
        tdc = d_item->tdc;

        tdc_start = d_item->pos;
        tdc_end = tdc_start + d_item->tdc_len;

        // XXX have this whole conditional as a flag
        if (INTERVALS_OVERLAP(tdc_start, tdc_end, pos_start, pos_end)) {
            tdc_left = d_item->tdc_len - d_item->consumed;
            size = MIN(tdc_left, chunk_len);

            if (is_dirty) {
                if (ucafs_storetdc(context, tdc, d_item->consumed, size,
                                   &nbytes)) {
                    goto out;
                }
            }

            d_item->consumed += size;
            chunk_len -= size;

            /* if the TDC is "consumed", time to release it */
            if (d_item->consumed == d_item->tdc_len) {
                if (afs_indexFlags[tdc->index] & IFDataMod) {
                    afs_indexFlags[tdc->index] &= ~IFDataMod;
                    afs_stats_cmperf.cacheCurrDirtyChunks--;
                    afs_indexFlags[tdc->index] &= ~IFDirtyPages;
                    if (sync & AFS_VMSYNC_INVAL) {
                        afs_indexFlags[tdc->index] &= ~IFAnyPages;
                    }
                }

                ObtainWriteLock(&tdc->lock, 628);
                tdc->f.states &= ~DWriting;
                tdc->dflags |= DFEntryMod;
                ReleaseWriteLock(&tdc->lock);

                /* release the entry */
                afs_PutDCache(tdc);
                d_item->inuse = 0;
            }
        } else {
            break;
        }

        tdc_count++;
        curr = (curr + 1) % len;
    }

    *tdc_seen = tdc_count;
    ret = 0;
out:
    if (is_dirty && store_clean_context(context, &output, ret) == 0) {
        // TODO afs_ProcessFS
    }

    return ret;
}

int
ucafs_store(struct vcache * avc, struct vrequest * areq, int sync)
{
    int ret, abyte, afs_chunks, dirty_chunks, count, i, k, first,
        try_next_chunk, bytes_left;
    afs_hyper_t old_dv, new_dv;
    size_t max_tdc_per_segment, nbytes, tdc_seen;
    struct dcache * tdc;
    dcache_item_t *dclist = NULL, *dc_entry;
    store_context_t * context;
    char * path;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;

    if (!UCAFS_IS_CONNECTED || __is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    /* lets flush all the data */
    osi_VM_StoreAllSegments(avc);
    if (AFS_IS_DISCONNECTED && !AFS_IN_SYNC) {
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
        return -1;
    }

    if ((context->buffer = ALLOC_XFER_BUFFER) == NULL) {
        ERROR("allocating context buffer failed\n");
        goto out;
    }

    if ((tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn)) == NULL) {
        ERROR("allocating afs_Conn failed\n");
        goto out;
    }

    context->buflen = DEFAULT_XFER_SIZE;
    context->id = -1;
    context->uc_conn = __get_conn();
    context->path = path;
    context->avc = avc;
    context->tc = tc;
    context->rx_conn = rx_conn;

    /* compute the sizes of our chunks */
    max_tdc_per_segment = CHUNK_RATIO(AFS_LOGCHUNK, UCAFS_CHUNK_LOG);

    /* allocate our list */
    dclist = (dcache_item_t *)kzalloc(
        max_tdc_per_segment * sizeof(dcache_item_t), GFP_KERNEL);
    if (dclist == NULL) {
        ERROR("allocation failed for dcache_items\n");
        goto out;
    }

    dirty_chunks = i = count = first = abyte = 0;
    bytes_left = avc->f.m.Length;
    afs_chunks = AFS_CHUNK(bytes_left) + 1;

    ConvertWToSLock(&avc->lock);

    /* iterate through the tdc list */
    while (afs_chunks > 0) {
        /* get the TDC entry */
        if ((tdc = afs_FindDCache(avc, abyte)) == NULL) {
            break;
        }

        /* if they have the same file ID */
        dc_entry = &dclist[i];
        if (dc_entry->inuse) {
            // we are replacing an existing entry
            if (dc_entry->is_dirty) {
                dc_entry->is_dirty = 0;
                dirty_chunks--;
            }

            if (i == first) {
                first = (first + 1) % max_tdc_per_segment;
            }
        }

        dc_entry->inuse = 1;
        dc_entry->tdc = tdc;
        dc_entry->pos = AFS_CHUNKTOBASE(tdc->f.chunk);
        dc_entry->consumed = 0;
        dc_entry->chunk_no = tdc->f.chunk;

        // XXX Unsure on if to take the xdcache here since we are reading from
        // the index flags table. Looked at afs_ObtainDCacheForWriting, it seems
        // once the tdc write lock is held, this variable can be examined
        ObtainSharedLock(&tdc->lock, 8760);
        if (afs_indexFlags[tdc->index] & IFDataMod) {
            dirty_chunks++;
            dc_entry->is_dirty = 1;
        }

        dc_entry->tdc_len = tdc->f.chunkBytes;
        ReleaseSharedLock(&tdc->lock);

        // increment our variables
        i = (i + 1) % max_tdc_per_segment;
        count = (count < max_tdc_per_segment) ? count + 1 : count;

        /* now process if we have a sufficient number of tdc
         * entries gathered */
        if (count >= max_tdc_per_segment && dirty_chunks) {
            tdc_seen = 0;
        next_chunk:
            try_next_chunk = 1;

            ret = ucafs_storesegment(context, dclist, first, count, avc, areq,
                                     sync, path, &new_dv, &nbytes, &tdc_seen);
            if (ret) {
                ERROR("chunk_store failed ret = %d", ret);
                goto out1;
            }

            bytes_left -= nbytes;

            /* for each tdc seen, lets rid of those we stored fully */
            for (k = 0; k < tdc_seen; k++) {
                dc_entry = &dclist[first];
                if (dc_entry->consumed < dc_entry->tdc_len) {
                    break;
                }

                // clear the entry and move the first
                if (dc_entry->is_dirty) {
                    dc_entry->is_dirty = 0;
                    dirty_chunks--;
                }

                dc_entry->inuse = 0;
                try_next_chunk = 0;
                first = (first + 1) % max_tdc_per_segment;
                count--;
            }

            /* if the tdc is not fully consumed, that means we might have
             * another chunk to process */
            if (try_next_chunk) {
                goto next_chunk;
            }
        }

        afs_chunks--;
        abyte += AFS_CHUNKSIZE(0);
    }

    /* stores the last chunk */
    if (dirty_chunks) {
        tdc_seen = 0;
        goto next_chunk;
    }

    /* TODO upgrade the tdc version number */

    ret = 0;
out1:
    UpgradeSToWLock(&avc->lock, 629);

    /* put back all the tdc entries still in use */
    if (ret) {
        for (k = 0; k < count; k++) {
            if (dclist[k].inuse) {
                afs_PutDCache(dclist[k].tdc);
            }
        }
    }

out:
    if (tc) {
        afs_PutConn(tc, rx_conn, 0);
    }

    if (context->uc_conn) {
        __put_conn(context->uc_conn);
    }

    if (context->buffer) {
        FREE_XFER_BUFFER(context->buffer);
    }

    kfree(context);

    kfree(path);
    kfree(dclist);
    return ret;
}
