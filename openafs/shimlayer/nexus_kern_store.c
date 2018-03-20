#include "nexus_module.h"
#include "nexus_json.h"
#include "nexus_util.h"
#include "nexus_kern.h"
#include "nexus_volume.h"

static int
nexus_store_upload(struct rx_call * afs_call, uint8_t * buffer, int tlen, int * byteswritten)
{
    uint8_t * buf = buffer;

    afs_int32 nbytes     = 0;
    afs_int32 bytes_left = tlen;
    afs_int32 size       = 0;

    int ret = 0;

    *byteswritten = 0;

    /* send the data to the server */
    RX_AFS_GUNLOCK();
    
    while (bytes_left > 0) {
        size = MIN(MAX_FILESERVER_TRANSFER_BYTES, bytes_left);

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
nexus_store_encrypt(struct nexus_volume * vol,
                    char                * path,
                    size_t                offset,
                    size_t                buflen,
                    size_t                filesize)
{
    char * cmd_str   = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;


    cmd_str = kasprintf(GFP_KERNEL, generic_databuf_command, AFS_OP_ENCRYPT, path, offset, buflen, filesize);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
        return -1;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();


    if (ret == -1) {
	NEXUS_ERROR("Error Sending Nexus Command\n");
	ret = -1;
	goto out;
    }

    // handle response...
    {
        struct nexus_json_param resp[1] = { { "code", NEXUS_JSON_S32, { 0 } } };

        s32 ret_code = 0;

	ret = nexus_json_parse(resp_data, resp, 1);

	if (ret != 0 && resp[0].val == 0) {
            NEXUS_ERROR("Could not parse JSON response\n");
            ret = -1;
            goto out;
        }

	ret_code = (s32)resp[0].val;

	if (ret_code != 0) {
            ret = -1;
            goto out;
        }
    }

out:
    if (cmd_str) {
        nexus_kfree(cmd_str);
    }

    return ret;
}

static int
nexus_store_transfer(struct nexus_volume * vol,
                     struct rx_call      * afs_call,
                     struct dcache       * tdc,
                     char                * path,
                     size_t                offset,
                     size_t                filesize,
                     int                 * transferred)
{
    struct osi_file * fp = NULL;

    int nbytes_uploaded = 0;
    int nbytes          = 0;
    int size            = 0;

    int ret = -1;


    // copy a chunk of the data into the transfer buffer
    // OS panic on failure :)
    fp = afs_CFileOpen(&tdc->f.inode);

    // the nexus_databuffer_size is at least the chunk length
    // this operation accounts for small chunks
    size = MIN(tdc->f.chunkBytes, NEXUS_DATABUF_SIZE);

    nbytes = afs_osi_Read(fp, -1, nexus_databuffer_ptr, size);

    osi_UFSClose(fp);

    if (size != nbytes) {
        NEXUS_ERROR("error reading chunk file. tried=%d, got=%d\n", size, nbytes);
        return -1;
    }


    // encrypt the buffer
    ret = nexus_store_encrypt(vol, path, offset, nbytes, filesize);

    if (ret != 0) {
        NEXUS_ERROR("nexus_store_encrypt FAILED\n");
        return -1;
    }


    // ship the data to the fileserver
    ret = nexus_store_upload(afs_call, nexus_databuffer_ptr, nbytes, &nbytes_uploaded);

    if (ret != 0) {
        NEXUS_ERROR("nexus_store_upload FAILED\n");
        return -1;
    }

    return 0;
}

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
    struct nexus_volume * vol = NULL;

    unsigned long flags = 0;

    int filesize     = avc->f.m.Length;
    int offset       = base;

    int bytes_stored = 0;
    int nbytes       = 0;

    afs_uint32 i = 0;

    int ret = -1;


    vol = nexus_get_volume(path);

    if (vol == NULL) {
        return -1;
    }

    spin_lock_irqsave(nexus_databuffer_lock, flags);

    avc->f.truncPos = AFS_NOTRUNC;

    // start uploading each chunk
    for (i = 0; i < nchunks; i++) {
        // TODO add code for afs_wakeup for cases file is locked at the server
        ret = nexus_store_transfer(vol, afs_call, dclist[i], path, offset, filesize, &nbytes);

        if (ret != 0) {
            NEXUS_ERROR("could not transfer chunk (path=%s, chunk_num=%d) error :(",
                        path, dclist[i]->f.chunk);
            goto out;
        }

        // TODO add code for "small" tdc entries: send a buffer of zeros

        bytes_stored += nbytes;
        offset       += nbytes;
    }

    ret = 0;
out:
    spin_unlock_irqrestore(nexus_databuffer_lock, flags);

    nexus_put_volume(vol);

    return ret;
}
