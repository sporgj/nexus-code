#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_store: " fmt, ##args)

static int
store_init_fserv(store_context_t * ctx,
                 afs_size_t base,
                 afs_size_t len,
                 struct vrequest * areq);

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
    if ((nbytes = rx_Write(afs_call, buffer, tlen)) != tlen) {
        ERROR("afs_server exp=%d, act=%d\n", tlen, (int)nbytes);
        ret = -1;
    }

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
    if (StartAFSX_fetchstore_data(uspace_call, ctx->id, size)) {
        ERROR("StartAFSX_upload_file failed\n");
        goto out;
    }

    /* send the bytes over */
    if ((nbytes = rx_Write(uspace_call, ctx->buffer, size)) != size) {
        ERROR("send error: exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    /* reread the bytes into the buffer */
    if ((nbytes = rx_Read(uspace_call, ctx->buffer, size)) != size) {
        ERROR("recv error: exp=%d, act=%u\n", size, nbytes);
        goto out;
    }

    *bytesread = nbytes;

    ret = 0;
out:
    EndAFSX_fetchstore_data(uspace_call);
    rx_EndCall(uspace_call, ret);
    return ret;
}

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
ucafs_storesegment(dcache_item_t * dclist,
                   int first,
                   int len,
                   struct vcache * avc,
                   struct vrequest * areq,
                   int sync,
                   char * path,
                   afs_hyper_t * new_dv,
                   size_t * nbytes,
                   size_t * tdc_seen)
{
    int ret, j, tdc_start, tdc_end, pos_start, pos_end, curr, is_dirty;
    int tdc_count, tdc_left, bytes_left, chunk_len = UCAFS_CHUNK_SIZE;
    struct dcache_item * d_item;
    struct dcache * tdc;

    /* get the index of the first element */
    pos_start = dclist[first].pos + dclist[first].consumed;
    pos_end = pos_start + chunk_len;

    /* loop through the tdc entries and see if there's anyone to save to disk */
    is_dirty = 0;
    curr = first;
    for (j = 0; j < len; j++) {
        d_item = &dclist[curr];
        tdc_start = d_item->pos;
        tdc_end = tdc_start + d_item->tdc_len;

        /* check if we can start storing */
        if ((tdc_start >= pos_start && tdc_start < pos_end)
            || (tdc_end >= pos_start && tdc_end < pos_end)) {
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
        // TODO initialize context here
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
        if ((tdc_start >= pos_start && tdc_start < pos_end)
            || (tdc_end >= pos_start && tdc_end < pos_end)) {
            tdc_left = d_item->tdc_len - d_item->consumed;
            bytes_left = MIN(tdc_left, chunk_len);

            // TODO call routine here

            d_item->consumed += bytes_left;
            chunk_len -= bytes_left;

            // TODO if the tdc is completely stored, update AFS stuff here
        } else {
            break;
        }

        tdc_count++;
        curr = (curr + 1) % len;
    }

    *tdc_seen = tdc_count;
    ret = 0;
out:
    return ret;
}

int
ucafs_store(struct vcache * avc, struct vrequest * areq, int sync)
{
    int ret, abyte, afs_chunks, dirty_chunks, count, i, k, first,
        try_next_chunk, bytes_left;
    afs_hyper_t old_dv, new_dv;
    size_t max_tdc_per_segment, max_segment_per_tdc, nbytes, tdc_seen;
    struct dcache * tdc;
    dcache_item_t *dclist = NULL, *dc_entry;
    char * path;

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

    /* compute the sizes of our chunks */
    max_tdc_per_segment = CHUNK_RATIO(AFS_LOGCHUNK, UCAFS_CHUNK_LOG);
    max_segment_per_tdc = CHUNK_RATIO(UCAFS_CHUNK_LOG, AFS_LOGCHUNK);

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
    while (afs_chunks) {
        /* get the TDC entry */
        tdc = afs_FindDCache(avc, abyte);
        if (!tdc) {
            break;
        }

        afs_PutDCache(tdc);

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

        ObtainWriteLock(&tdc->lock, 8760);
        if (afs_indexFlags[tdc->index] & IFDataMod) {
            dirty_chunks++;
            dc_entry->is_dirty = 1;
        }

        dc_entry->tdc_len = tdc->f.chunkBytes;
        ReleaseWriteLock(&tdc->lock);

        // increment our variables
        i = (i + 1) % max_tdc_per_segment;
        count = (count < max_tdc_per_segment) ? count + 1 : count;

        /* now process if we have a sufficient number of tdc
         * entries gathered */
        if (count >= max_tdc_per_segment && dirty_chunks) {
            tdc_seen = 0;
next_chunk:
            try_next_chunk = 1;

            ret = ucafs_storesegment(dclist, first, count, avc, areq, sync,
                                     path, &new_dv, &nbytes, &tdc_seen);
            if (ret) {
                ERROR("chunk_store failed ret = %d", ret);
                goto out1;
            }

            bytes_left -= nbytes;

            /* for each tdc seen, lets rid of those we stored fully */
            for (k = 0; k < tdc_seen; k++) {
                dc_entry = &dclist[first];

                if (dc_entry->consumed == dc_entry->tdc_len) {
                    // clear the entry and move the first
                    if (dc_entry->is_dirty) {
                        dc_entry->is_dirty = 0;
                        dirty_chunks--;
                    }

                    dc_entry->inuse = 0;

                    try_next_chunk = 0;
                    count--;

                    first = (first + 1) % max_tdc_per_segment;
                }
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
        ret = ucafs_storesegment(dclist, first, count, avc, areq, sync, path,
                                 &new_dv, &nbytes, &tdc_seen);
        if (ret) {
            ERROR("chunk_store failed ret = %d", ret);
            goto out1;
        }

        bytes_left -= nbytes;
    }

    ret = 0;
out1:
    UpgradeSToWLock(&avc->lock, 629);
out:
    kfree(path);
    kfree(dclist);
    return AFSX_STATUS_NOOP;
}

static int
store_init_fserv(store_context_t * ctx,
                 afs_size_t base,
                 afs_size_t len,
                 struct vrequest * areq)
{
    int ret = -1, tlen = ctx->total_len, code;
    struct rx_call * afs_call = NULL;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;
    struct AFSStoreStatus instatus;
    struct vcache * avc = ctx->avc;

    if ((tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn)) == NULL) {
        ERROR("allocating afs_Conn failed\n");
        goto out;
    }

    /* send the request to the fileserver */
    RX_AFS_GUNLOCK();
    afs_call = rx_NewCall(tc->id);
    RX_AFS_GLOCK();

    if (afs_call) {
        /* set the date and time */
        instatus.Mask = AFS_SETMODTIME;
        instatus.ClientModTime = avc->f.m.Date;

        RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
        // if the server is rrunning in 64 bits
        if (!afs_serverHasNo64Bit(tc)) {
            ctx->srv_64bit = 1;
            code = StartRXAFS_StoreData64(afs_call, &avc->f.fid.Fid, &instatus,
                                          base, len, tlen);
        } else {
            // XXX check for total_len > 2^32 - 1
            code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus,
                                        base, len, tlen);
        }
#else
        code = StartRXAFS_StoreData(afs_call, &avc->f.fid.Fid, &instatus, base,
                                    len, tlen);
#endif
    } else {
        code = -1;
    }

    RX_AFS_GLOCK();

    if (code) {
        ERROR("starting fileserver transfer FAILED\n");
        goto out;
    }

    ctx->afs_call = afs_call;
    ctx->rx_conn = rx_conn;
    ctx->tc = tc;

    ret = 0;
out:
    return ret;
}
