#include "afs_secure.h"
#include "afsx.h"

static int fetch_read(void * rock, afs_uint32 len, afs_uint32 * bytesread)
{

}

static int fetch_write(void * rock, struct osi_file * fp, afs_uint32 offset,
        afs_uint32 tlen, afs_uint32 * byteswritten)
{

}

static int fetch_close(void * rock, struct vcache * avc, struct dcache * adc,
        struct afs_FetchOutput * outputs)
{

}

static int fetch_destroy(void ** rock, afs_int32 error)
{

}

static struct fetchOps ops = {
    .read = fetch_read,
    .write = fetch_write,
    .close = fetch_close,
    .destroy = fetch_destroy
};

typedef struct {
    void * buffer;
    afs_int32 length;
    struct rx_call * afs_rx;
} ucafs_ctx_t;

static int fetch_init(ucafs_ctx_t ** context, struct vcache * avc)
{
    struct afs_conn * tc;
    ucafs_ctx_t * ctx = kmalloc(sizeof(ucafs_ctx_t), GFP_KERNEL);
    if (ctx == NULL) {
        printk(KERN_ERR "fetch_init: could not allocate ctx\n");
        return -1;
    }

    ctx->buffer = (void *)__get_free_page(GFP_KERNEL);
    if (ctx->buffer == NULL) {
        kfree(ctx);
        printk(KERN_ERR "fetch_init: could not allocate context buffer\n");
        return -1;
    }

    tc = afs_Conn(&avc->f.fid, areq, 0, &rx_conn);
    ctx->afs_rx = rx_NewCall(tc->id);

#ifdef AFS_64BIT_CLIENT
    if (!afs_serverHasNo64Bit(tc)) {
        code = StartRXAFS_FetchData64(
            afs_call, (struct AFSFid *)&avc->f.fid.Fid, 0, total_len);
    } else {
        code = StartRXAFS_FetchData(afs_call, (struct AFSFid *)&avc->f.fid.Fid,
                                    0, total_len);
    }
#else
    code = StartRXAFS_FetchData(afs_call, (struct AFSFid *)&avc->f.fid.Fid, 0,
                                total_length);
#endif

    // read the 32 bit length field
    if (!code) {
        RX_AFS_GUNLOCK();
        bytes = rx_Read(ctx->afs_rx, (char *)&length, sizeof(afs_int32));
        RX_AFS_GLOCK();

        if (bytes == sizeof(afs_int32)) {
            ctx->length = ntohl(length);
        } else {
            // cleanup and return
            RX_AFS_GUNLOCK();
            printk(KERN_ERR "fetch_init: Server returning bs\n");
            RX_AFS_GLOCK();
        }
    }
    return 0;
}

int UCAFS_fetch(struct vcache * avc)
{
    int ret;
    const char * path;

    /* check that the AVC has everything */
    if (!AFSX_IS_CONNECTED) {
        return AFSX_STATUS_NOOP;
    }

    if (avc->flags & IFCrypto) {
        retunr AFSX_STATUS_NOOP;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return AFSX_STATUS_NOOP;
    }

    if (fetch_init(&ctx, avc)) {
        goto out;
    }

out:
    return ret;
}
