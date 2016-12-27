#include "ucafs_kern.h"
#include "ucafs_mod.h"
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/page-flags.h>

static int
ucafs_storeupdateversion(struct vcache * avc,
                         afs_hyper_t oldDV,
                         afs_hyper_t newDV);

typedef struct dcache_item {
    bool is_dirty;
    int chunk_no;
    int pos;
    int len;
    struct dcache * tdc;
} dcache_item_t;

static int
store_clean_context(store_context_t * context,
                    struct AFSFetchStatus * out,
                    int error,
                    int * do_processfs)
{
    int code, buflen, ret = 0;
    struct AFSVolSync tsync;
    caddr_t buf_ptr;
    XDR xdrs;
    reply_data_t * reply = NULL;
    *do_processfs = 1;

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

    ret = ucafs_mod_send(UCAFS_MSG_XFER_EXIT, &xdrs, &reply, &code);
    if (ret) {
        ERROR("store_close, could not get response from uspace\n");
        goto next_op;
    }

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

    if (code) {
        *do_processfs = 0;
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
                   char * path,
                   afs_hyper_t * p_newdv)
{
    int ret = -1, pos_start, pos_end, bytes_left, i, len, written, code,
        total_bytes, processfs;
    caddr_t buf_ptr;
    XDR xdrs, *x_data;
    xfer_req_t xfer_req;
    xfer_rsp_t xfer_rsp;
    reply_data_t * reply = NULL;
    struct osi_file * fp = NULL;
    struct dcache * tdc;
    struct AFSFetchStatus output;
    struct page * page = NULL;
    struct vcache * avc = context->avc;
    char * data_bufptr = NULL;

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

    ERROR("setting up xdr\n");

    xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);
    /* lets start writing, we have to manully move the xdr */
    xfer_req = (xfer_req_t){.op = UCAFS_STORE,
                            .xfer_size = PAGE_SIZE,
                            .offset = pos_start,
                            .part_size = sum_bytes,
                            .file_size = context->total_size};
    /* create the request */
    if (!xdr_opaque(&xdrs, (caddr_t)&xfer_req, sizeof(xfer_req_t)) ||
        !xdr_string(&xdrs, &path, UCAFS_PATH_MAX)) {
        ERROR("error encoding XDR object\n");
        goto out;
    }

    /* after this, the READPTR_LOCK() gets released */
    ret = ucafs_mod_send(UCAFS_MSG_XFER_INIT, &xdrs, &reply, &code);
    if (ret || code) {
        ERROR("initializing store for %s (%d, %d)\n", path, pos_start, pos_end);
        goto out;
    }

    // read the response
    x_data = &reply->xdrs;
    if (!xdr_opaque(x_data, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t))) {
        ERROR("could not read response from init stored\n");
        goto out;
    }

    ERROR("response acquired, uaddr_t=%p\n", xfer_rsp.uaddr);

    context->id = xfer_rsp.xfer_id;
    /* we get to pin the user's pages and start the transfer */
    down_read(&dev->daemon->mm->mmap_sem);
    ret = get_user_pages(dev->daemon, dev->daemon->mm,
                         (unsigned long)xfer_rsp.uaddr, 1, 1, 1, &page, NULL);
    if (ret != 1) {
        up_read(&dev->daemon->mm->mmap_sem);
        ERROR("getting user pages failed: uaddr=%p\n", xfer_rsp.uaddr);
        goto out;
    }

    /* now lets kmap and start I/O */
    data_bufptr = kmap(page);
    up_read(&dev->daemon->mm->mmap_sem);

    /* now, lets start pushing the data around */
    total_bytes = 0;
    for (i = 0; i < count; i++) {
        tdc = dclist[i].tdc;
        fp = afs_CFileOpen(&tdc->f.inode);

        bytes_left = dclist[i].len;
        while (bytes_left > 0) {
            if ((buf_ptr = READPTR_LOCK()) == 0) {
                goto out1;
            }

            /* copy data to the daata buffer */
            len = MIN(bytes_left, xfer_rsp.buflen);
            afs_osi_Read(fp, -1, data_bufptr, len);

            /* create our xdrs and fake the pointers */
            xdrmem_create(&xdrs, buf_ptr, READPTR_BUFLEN(), XDR_ENCODE);
            if (!xdr_int(&xdrs, &context->id) || !xdr_int(&xdrs, &len)) {
                ERROR("xdr store_data failed\n");
                goto out1;
            }

            /* send the enchilada */
            ret = ucafs_mod_send(UCAFS_MSG_XFER_RUN, &xdrs, &reply, &code);
            if (ret || code) {
                ERROR("error from uspace code=%d\n", code);
                goto out1;
            }

            /* now send the whole thing, hold the lock on the ptr to avoid
             * any other process from writing over */
            if (store_write(context, buf_ptr, len, &written)) {
                goto out1;
            }

            kfree(reply);
            reply = NULL;

            total_bytes += len;
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
out1:
    /* unpin the page and release everything */
    kunmap(page);
    if (!PageReserved(page)) {
        SetPageDirty(page);
        page_cache_release(page);
    }
out:
    if (fp) {
        osi_UFSClose(fp);
    }

    if (reply) {
        kfree(reply);
    }

    store_clean_context(context, &output, ret, &processfs);
    if (processfs && ret == 0) {
        // then we have to augment the data version
        hadd32(*p_newdv, 1);

        UpgradeSToWLock(&avc->lock, 289);
        afs_ProcessFS(avc, &output, areq);
        ConvertWToSLock(&avc->lock);
    }

    READPTR_TRY_UNLOCK();

    return ret;
}

int
ucafs_store(struct vcache * avc, struct vrequest * areq, int sync)
{
    int ret = -1, abyte, afs_chunks, dirty_chunks, count, i, bytes_left,
        sum_bytes;
    afs_hyper_t old_dv, new_dv;
    size_t tdc_per_part, part_per_tdc;
    struct dcache * tdc;
    dcache_item_t *dclist = NULL, *dcitem;
    store_context_t * context;
    char * path;
    struct rx_connection * rx_conn = NULL;
    struct afs_conn * tc = NULL;

    if (UCAFS_IS_OFFLINE || ucafs_vnode_path(avc, &path) ||
        (avc->f.m.Length == 0)) {
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
                                      GFP_KERNEL);
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
            ERROR("tdc could not be retrieved. abyte=%d\n", abyte);
            goto out1;
        }

        dcitem = &dclist[i];

        /* lets check if the tdc entry is dirty */
        ObtainSharedLock(&tdc->lock, 8760);
        if (afs_indexFlags[tdc->index] & IFDataMod) {
            dirty_chunks++;
            dcitem->is_dirty = 1;
        }

        /* update the amount of data being processed */
        dcitem->len = tdc->f.chunkBytes;
        sum_bytes += dcitem->len;
        abyte += dcitem->len;
        ReleaseSharedLock(&tdc->lock);

        dcitem->tdc = tdc;
        dcitem->pos = AFS_CHUNKTOBASE(tdc->f.chunk);
        dcitem->chunk_no = tdc->f.chunk;

        i++;
        count++;

        if (count == tdc_per_part) {
        store_chunk:
            /* clear the list */
            if (dirty_chunks == 0) {
                goto skip_store;
            }

            if ((ret = ucafs_storesegment(context, dclist, count, sum_bytes,
                                          areq, sync, path, &new_dv))) {
                ERROR("ucafs_storesegment failed ret = %d", ret);
                goto out1;
            }

        skip_store:
            /* put back all the tdc entries, don't upgrade the version number */
            for (i = 0; i < count; i++) {
                afs_PutDCache(dclist[i].tdc);
            }

            sum_bytes = count = i = dirty_chunks = 0;
        }

        afs_chunks--;
    }

    /* if there a lingering chunks but count != tdc_per_part */
    if (dirty_chunks) {
        goto store_chunk;
    }

    ret = 0;
out1:
    UpgradeSToWLock(&avc->lock, 658);
    if (ret == 0) {
        avc->f.states &= ~CDirty;

        ucafs_storeupdateversion(avc, old_dv, new_dv);
    }

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

    kfree(context);
    kfree(path);

    return ret;
}

// function modified from afs, upgrades the version numbers of the avc and tdc
#define NCHUNKSATONCE 64
static int
ucafs_storeupdateversion(struct vcache * avc,
                         afs_hyper_t oldDV,
                         afs_hyper_t newDV)
{
    int index, moredata, off, j, i, safety, minj, hash = DVHash(&avc->f.fid),
                                                  afs_dvhack = 0, foreign = 0;
    afs_int32 origCBs;
    struct dcache *tdc, **dcList;
    afs_hyper_t h_unset;
    hones(h_unset);

    dcList = (struct dcache **)kmalloc(NCHUNKSATONCE * sizeof(struct dcache *),
                                       GFP_KERNEL);
    if (dcList == NULL) {
        ERROR("could not allocate dcList\n");
        return -1;
    }
    origCBs = afs_allCBs;

    minj = 0;

    do {
        moredata = FALSE;
        memset(dcList, 0, NCHUNKSATONCE * sizeof(struct dcache *));

        /* overkill, but it gets the lock in case GetDSlot needs it */
        ObtainWriteLock(&afs_xdcache, 285);

        for (j = 0, safety = 0, index = afs_dvhashTbl[hash];
             index != NULLIDX && safety < afs_cacheFiles + 2;
             index = afs_dvnextTbl[index]) {

            if (afs_indexUnique[index] == avc->f.fid.Fid.Unique) {
                tdc = afs_GetValidDSlot(index);
                if (!tdc) {
                    /* This is okay; since manipulating the dcaches at this
                     * point is best-effort. We only get a dcache here to
                     * increment the dv and turn off DWriting. If we were
                     * supposed to do that for a dcache, but could not
                     * due to an I/O error, it just means the dv won't
                     * be updated so we don't be able to use that cached
                     * chunk in the future. That's inefficient, but not
                     * an error. */
                    continue;
                }
                ReleaseReadLock(&tdc->tlock);

                if (!FidCmp(&tdc->f.fid, &avc->f.fid) && tdc->f.chunk >= minj) {
                    off = tdc->f.chunk - minj;
                    if (off < NCHUNKSATONCE) {
                        /* this is the file, and the correct chunk range */
                        if (j >= NCHUNKSATONCE)
                            osi_Panic("Too many dcache entries in range\n");
                        dcList[j++] = tdc;
                    } else {
                        moredata = TRUE;
                        afs_PutDCache(tdc);
                        if (j == NCHUNKSATONCE)
                            break;
                    }
                } else {
                    afs_PutDCache(tdc);
                }
            }
        }
        ReleaseWriteLock(&afs_xdcache);

        for (i = 0; i < j; i++) {
            /* Iterate over the dcache entries we collected above */
            tdc = dcList[i];
            ObtainSharedLock(&tdc->lock, 677);

            /* was code here to clear IFDataMod, but it should only be done
             * in storedcache and storealldcache.
             */
            /* Only increase DV if we had up-to-date data to start with.
             * Otherwise, we could be falsely upgrading an old chunk
             * (that we never read) into one labelled with the current
             * DV #.  Also note that we check that no intervening stores
             * occurred, otherwise we might mislabel cache information
             * for a chunk that we didn't store this time
             */
            /* Don't update the version number if it's not yet set. */
            if (!hsame(tdc->f.versionNo, h_unset) &&
                hcmp(tdc->f.versionNo, oldDV) >= 0) {

                if ((!(afs_dvhack || foreign) &&
                     hsame(avc->f.m.DataVersion, newDV)) ||
                    ((afs_dvhack || foreign) && (origCBs == afs_allCBs))) {
                    /* no error, this is the DV */

                    UpgradeSToWLock(&tdc->lock, 678);
                    hset(tdc->f.versionNo, avc->f.m.DataVersion);
                    tdc->dflags |= DFEntryMod;
                    /* DWriting may not have gotten cleared above, if all
                     * we did was a StoreMini */
                    tdc->f.states &= ~DWriting;
                    ConvertWToSLock(&tdc->lock);
                }
            }

            ReleaseSharedLock(&tdc->lock);
            afs_PutDCache(tdc);
        }

        minj += NCHUNKSATONCE;

    } while (moredata);

    if (hcmp(avc->mapDV, oldDV) >= 0) {
        if ((!(afs_dvhack || foreign) && hsame(avc->f.m.DataVersion, newDV)) ||
            ((afs_dvhack || foreign) && (origCBs == afs_allCBs))) {
            hset(avc->mapDV, newDV);
            avc->f.states &= ~CDirty;
        }
    }

    return 0;
}
