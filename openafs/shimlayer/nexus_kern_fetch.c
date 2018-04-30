#include "nexus_module.h"
#include "nexus_json.h"
#include "nexus_util.h"
#include "nexus_kern.h"
#include "nexus_volume.h"

static int
nexus_fetch_download(struct rx_call * afs_call, caddr_t buf, int bytes_left)
{
    afs_int32 nbytes = 0;
    afs_int32 size   = 0;

    int ret = 0;

    /* send the data to the server */

    while (bytes_left > 0) {
        size = MIN(MAX_FILESERVER_TRANSFER_BYTES, bytes_left);

        RX_AFS_GUNLOCK();
        nbytes = rx_Read(afs_call, buf, size);
        RX_AFS_GLOCK();

        if (nbytes != size) {
            NEXUS_ERROR("afs_server exp=%d, act=%d\n", size, (int)nbytes);
            ret = -1;
            goto out;
        }

        buf += size;
        bytes_left -= size;
    }

out:
    return ret;
}

static int
nexus_fetch_decrypt(struct nexus_volume * vol,
                    char                * path,
                    size_t                offset,
                    size_t                buflen,
                    size_t                filesize)
{
    char * cmd_str   = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;


    cmd_str = kasprintf(GFP_KERNEL,
                        generic_databuf_command,
                        AFS_OP_DECRYPT,
                        path,
                        offset,
                        buflen,
                        filesize);

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

nexus_ret_t
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
    struct nexus_volume * vol         = NULL;

    int filesize                      = avc->f.m.Length;

    int ret                           = NEXUS_RET_ERROR;


    vol = nexus_get_volume(path);

    if (vol == NULL) {
        return NEXUS_RET_NOOP;
    }


    while (nexus_iobuf.in_use == true) {
        AFS_GUNLOCK(); // drop the lock to allow the running process to continue

        if (wait_event_interruptible(nexus_iobuf.waitq, nexus_iobuf.in_use == false)) {
            nexus_put_volume(vol);
            return NEXUS_RET_ERROR;
        }

        AFS_GLOCK();
    }


    nexus_iobuf.in_use = true;

    // size < nexus_chunk_size
    ret = nexus_fetch_download(acall, nexus_iobuf.buffer, size);

    if (ret != 0) {
        NEXUS_ERROR("could not download data\n");
        goto out;
    }


    ret = nexus_fetch_decrypt(vol, path, base, size, filesize);

    if (ret != 0) {
        NEXUS_ERROR("could not decrypt file contents\n");
        goto out;
    }


    // write the chunk file
    {
        int nbytes = afs_osi_Write(fp, -1, nexus_iobuf.buffer, size);

        if (nbytes != size) {
            ret = NEXUS_RET_ERROR;

            NEXUS_ERROR("could not write decrypted contents to chunk file\n");
            goto out;
        }
    }

    adc->validPos = base + size;
    afs_osi_Wakeup(&adc->validPos);

    ret = NEXUS_RET_OK;
out:
    nexus_iobuf.in_use = false;
    wake_up_interruptible(&nexus_iobuf.waitq);

    nexus_put_volume(vol);

    return ret;
}
