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

static int
ucafs_store_chunk(store_context_t * ctx,
                  afs_size_t chunk_base,
                  afs_size_t tdc_base,
                  struct dcache * tdc,
                  int ratio,
                  size_t i,
                  struct dcache ** dcList,
                  struct vrequest * areq)
{
    int ret = -1, bytes_left, tdc_size, nbytes, len, chunk_len;
    int flen = ctx->avc->f.m.Length, tlen; // TODO what about truncPos?
    size_t j = i;
    struct osi_file * file;

    ret = AFSX_store_start(ctx->uc_conn, ctx->path, DEFAULT_XFER_SIZE, 0, flen,
                           &ctx->id, &ctx->fbox_len);
    if (ret) {
        ERROR("AFSX_store_start error ret=%d\n", ret);
        goto out;
    }

    ctx->total_len = tlen = flen + ctx->fbox_len;
    chunk_len = MIN(UCAFS_CHUNK_SIZE, tlen - chunk_base);

    ret = store_init_fserv(ctx, chunk_base, chunk_len, UCAFS_CHUNK_SIZE, areq);
    if (ret) {
        ERROR("init_fserv error ret=%d\n", ret);
        goto out;
    }

    /* start storing the file */
    while (chunk_len > 0) {
        file = afs_CFileOpen(&tdc->f.inode);
        if (file == NULL) {
            ERROR("opening tdc chunk=%d\n", tdc->f.chunk);
            return -1;
        }

        tdc_size = tdc->f.chunkBytes;
        bytes_left = MIN(chunk_len, tdc_size);
        while (bytes_left > 0) {
            // send data to be encrypted
            len = MIN(bytes_left, ctx->buflen);

            // XXX check for return varible
            afs_osi_Read(file, -1, ctx->buffer, len);

            if (store_read(ctx, len, &nbytes)) {
                goto out;
            }

            if (store_write(ctx->afs_call, ctx->buffer, nbytes, &nbytes)) {
                goto out;
            }

            bytes_left -= len;
            chunk_len -= len;
            tdc_len -= len;
        }

        osi_UFSClose(file);

        if (tdc_len == 0) {
            // then we have to set the tdc as saved
            if (afs_indexFlags[tdc->index] & IFDataMod) {
                afs_indexFlags[tdc->index] &= ~IFDataMod;
                afs_stats_cmperf.cacheCurrDirtyChunks--;
                afs_indexFlags[tdc->index] &= ~IFDirtyPages;
                if (sync & AFS_VMSYNC_INVAL) {
                    // mark entry as having no pages, now reclaimable
                    afs_indexFlags[tdc->index] &= ~IFAnyPages;
                }
            }

            UpgradeSToWLock(&tdc->lock, 628);
            tdc->f.states &= ~DWriting;
            tdc->dflags |= DFEntryMod;
            ReleaseWriteLock(&tdc->lock);
            afs_PutDCache(tdc);
            dclist[j] = NULL;
        }

        /* if we have more tdc entries to go */
        if (chunk_len > 0) {
            // we have to read the next tdc entry
            if ((tdc = dcList[++j]) == NULL) {
                ERROR("there is no next tdc");
                goto out;
            }
        }
    }

    ret = 0;
out:
    if (ctx->id != -1) {
        AFSX_store_end(ctx->uc_conn, ctx->id);
    }

    return ret;
}

/**
 * This receives a call from afs_StoreAllSegments
 */
int
ucafs_store_chunk(store_context_t * context,
                  struct dcache ** dcList,
                  struct vcache * avc,
                  struct vrequest * areq,
                  int sync,
                  afs_size_t first,
                  afs_hyper_t * anewDV,
                  afs_size_t * amaxStoredLength)
{
    int ret = -1;
    afs_size_t base, chunk_base;
    size_t i;
    struct dcache * tdc;
    store_context_t * ctx = NULL;
    char * path = NULL;

    if (!UCAFS_IS_CONNECTED || __is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    ctx = (store_context_t *)kzalloc(sizeof(store_context_t), GFP_KERNEL);
    if (ctx == NULL) {
        kfree(path);
        return AFSX_STATUS_NOOP;
    }

    ctx->id = -1;
    ctx->avc = avc;
    ctx->path = path;
    ctx->uc_conn = __get_conn();
    ctx->buflen = DEFAULT_XFER_SIZE;
    if ((ctx->buffer = ALLOC_XFER_BUFFER) == NULL) {
        ERROR("allocating buffer failed\n");
        goto out;
    }

    ret = AFSX_STATUS_ERROR;

    /**
     * lets start gathering the tdc entries
     */
    for (i = 0; i < high;) {
        if ((tdc = dcList[j])) {
            // find the corresponding chunk
            base = AFS_CHUNKTOBASE(tdc->f.chunk);

            // get the start of our chunk to compute
            chunk_base = UCAFS_BASEOFFSET(base);

            ucafs_storesegment(chunk_base, tdc, i, dcList, areq);
        }
    }

    ret = 0;
out:
    kfree(path);
    FREE_XFER_BUFFER(ctx->buffer);
    kfree(ctx);
    return ret;
}

int
ucafs_kern_store(struct vcache * avc, struct vrequest * areq, int sync)
{
    int ret, hash, dirty_chunks, ratio, count, i, stored_bool = 0;
    afs_hyper_t old_dv, new_dv;
    afs_size_t nbytes, first;
    store_context_t * context;
    struct dcache ** dclist = NULL;

    if (!UCAFS_IS_CONNECTED || __is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    context = (store_context_t *)kzalloc(sizeof(store_context_t), GFP_KERNEL);
    if (context == NULL) {
        ERROR("allocation failed");
        return AFSX_STATUS_ERROR;
    }

    context->id = -1;
    context->avc = avc;
    context->path = path;
    context->uc_conn = __get_conn();
    context->buflen = DEFAULT_XFER_SIZE;
    if ((context->buffer = ALLOC_XFER_BUFFER) == NULL) {
        ERROR("allocating buffer failed\n");
        goto out;
    }

    /* lets start processing the tdc entries */
    hash = DVHash(&avc->f.fid);

    /* lets flush all the data */
    osi_VM_StoreAllSegments(avc);
    if (AFS_IS_DISCONNECTED && !AFS_IN_SYNC) {
        return ENETDOWN;
    }

    hset(old_dv, avc->f.m.DataVersion);
    hset(new_dv, avc->f.m.DataVersion);

    ConvertWToSLock(&avc->lock);

    ratio = UCAFS_COMPUTE_TDC_CHUNK_RATIO;
    dclist = (struct dcache **)kzalloc(ratio * sizeof(struct dcache *),
                                       GFP_KERNEL);
    if (dclist == NULL) {
        ERROR("allocating dcache list failed\n");
        goto out;
    }

    index = afs_dvhashTbl[hash];
    do {
        ObtainWriteLock(&afs_xdcache, 459);
        dirty_chunks = 0;

        for (j = 0; index != NULLIDX;) {
            if (afs_indexUnique[index] == avc->f.fid.Fid.Unique) {
                if (afs_indexFlags[index] & IFDataMod) {
                    dirty_chunks++;
                }

                tdc = afs_GetValidDSlot(index);
                if (!tdc) {
                    ReleaseWriteLock(&afs_xdcache);
                    goto out1;
                }
                ReleaseReadLock(&tdc->tlock);

                if (!FidCmp(&tdc->f.fid, &avc->f.fid)) {
                    if (dclist[i]) {
                        first = (first + 1) % ratio;
                        if (afs_indexFlags[dclist[i]->index] & IFDataMod) {
                            dirty_chunks--;
                        }
                        afs_PutDCache(dclist[i]);
                    } else if (count == 0) {
                        first = 0;
                    }

                    dclist[i] = tdc;
                    i = (i + 1) % ratio;
                    count++;
                }

                /* now process if we have a sufficient number of tdc
                 * entries gathered */
                if (count >= ratio && dirty_chunks) {
                    ret = ucafs_store_chunk(context, dclist, avc, areq, sync,
                                            first, &new_dv, &nbytes);
                    if (ret) {
						ERROR("chunk_store failed ret = %d", ret);
                        goto out;
                    }
					stored_bool = 1;
                }
            }

			index = afs_dvnextTbl[index];
        }

        /* if our number of tdc entries is not filled */
		if (stored_bool && dirty_chunks) {
            ret = ucafs_store_chunk(context, dclist, avc, areq, sync,
                                            first, &new_dv, &nbytes);

			if (ret) {
				ERROR("chunk_store failed ret = %d", ret);
				goto out;
			}
		}

        ReleaseWriteLock(&afs_xdcache);
    } while (1);

    ret = 0;
out:
    return ret;
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
