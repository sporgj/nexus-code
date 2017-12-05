#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <uv.h>

#include "third/log.h"
#include "third/xdr.h"
#include "third/xdr_prototypes.h"

#include "ucafs_header.h"

#include "uc_rpc.h"
#include "uc_uspace.h"
#include "uc_utils.h"

#define UCAFS_MOD_FILE "/dev/ucafs_mod"

static FILE * ucafs_mod_fid = NULL;

mid_t msg_counter;
uv_mutex_t mut_msg_counter;

static inline mid_t
ucrpc__genid(void)
{
    mid_t counter;
    uv_mutex_lock(&mut_msg_counter);
    counter = (++msg_counter);
    uv_mutex_unlock(&mut_msg_counter);

    return counter;
}

typedef struct xdr_inata {
    XDR xdrs;
    uint8_t data[0];
} xdr_data_t;

typedef struct xdr_outsp {
    XDR xdrs;
    ucrpc_msg_t msg;
} xdr_rsp_t;

#define XDROUT_DATALEN 64
#define XDROUT_TOTALLEN XDROUT_DATALEN + sizeof(XDR) + sizeof(ucrpc_msg_t)

/** we are going to have 3 buffers */
uint8_t in_buffer[UCAFS_DATA_BUFLEN], out_buffer[UCAFS_DATA_BUFLEN];
ucrpc_msg_t in_rpc = {0};

int
setup_mod()
{
    int len, status, ret, fno;
    size_t nbytes;
    xdr_data_t * x_data = (xdr_data_t *)in_buffer;
    xdr_rsp_t * x_rsp = (xdr_rsp_t *)out_buffer;
    ucrpc_msg_t *in_msg = &in_rpc, *out_msg = &x_rsp->msg;
    XDR *xdr_in = &x_data->xdrs, *xdr_out = &x_rsp->xdrs;

    uv_mutex_init(&mut_msg_counter);

    if (ucafs_mod_fid) {
        return 0;
    }

    if ((ucafs_mod_fid = fopen(UCAFS_MOD_FILE, "rb+")) == NULL) {
        uerror("opening '%s' failed", UCAFS_MOD_FILE);
        perror("Error: ");
        return -1;
    }

    fno = fileno(ucafs_mod_fid);

    /* send all the paths */
    for (size_t i = 0; i < global_supernode_count; i++) {
        sds path = sdsnew(global_supernode_paths[i]);
        path = sdscat(path, "/");
        path = sdscat(path, UCAFS_WATCH_DIR);
        
        if ((ret = ioctl(fno, IOCTL_ADD_PATH, path))) {
            uerror("ioctl ADD_PATH (%s) failed\n", path);
            sdsfree(path);
            return -1;
        }

        log_info("Added: %s", path);
        sdsfree(path);
    }

    /* set the memory map */
    if ((ret = ioctl(fno, IOCTL_MMAP_SIZE, &global_xfer_buflen))) {
        uerror("ioctl MMAP_SIZE failed");
        return -1;
    }

    /* mmap the xfer address to kernel memory */
    global_xfer_addr = mmap(NULL, global_xfer_buflen, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fno, 0);
    if (global_xfer_addr == (void *)-1) {
        log_fatal("mmap failed (size=%zu) :(", global_xfer_buflen);
        return -1;
    }

    uinfo("mmap %p for %zu bytes", global_xfer_addr, global_xfer_buflen);

    while (1) {
        nbytes = fread(in_msg, 1, sizeof(ucrpc_msg_t), ucafs_mod_fid);
        if (nbytes == sizeof(ucrpc_msg_t)) {
            /* read the data on the wire */
            nbytes = fread(x_data->data, 1, in_msg->len, ucafs_mod_fid);

            /* create our XDR data */
            xdrmem_create(xdr_in, (caddr_t) x_data->data, in_msg->len, XDR_DECODE);
            xdrmem_create(xdr_out, x_rsp->msg.payload, PAGE_SIZE, XDR_ENCODE);

            /* dispatch to the corresponding function */
            switch (in_msg->type) {
            case UCAFS_MSG_PING:
                status = uc_rpc_ping(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_LOOKUP:
            case UCAFS_MSG_FILLDIR:
            case UCAFS_MSG_CREATE:
            case UCAFS_MSG_REMOVE:
                status = uc_rpc_dirops(in_msg->type, xdr_in, xdr_out);
                break;
            case UCAFS_MSG_SYMLINK:
                status = uc_rpc_symlink(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_HARDLINK:
                status = uc_rpc_hardlink(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_RENAME:
                status = uc_rpc_rename(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_STOREACL:
                status = uc_rpc_storeacl(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_CHECKACL:
                status = uc_rpc_checkacl(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_XFER_INIT:
                status = uc_rpc_xfer_init(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_XFER_RUN:
                status = uc_rpc_xfer_run(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_XFER_EXIT:
                status = uc_rpc_xfer_exit(xdr_in, xdr_out);
                break;
            default:
                break;
            }

            /* send the response */
            nbytes = xdr_out->x_private - xdr_out->x_base;
            *out_msg = (ucrpc_msg_t){.msg_id = ucrpc__genid(),
                                     .ack_id = in_msg->msg_id,
                                     .len = nbytes,
                                     .type = in_msg->type,
                                     .status = status };
            len = MSG_SIZE(out_msg);

            /* send the whole thing */
            nbytes = fwrite(out_msg, 1, len, ucafs_mod_fid);

            /*log_debug("{ uc_mod } type=%d id=%d status=%d in=(%zu, %d), "
                      "out=(%zu, %d)",
                      out_msg->type, out_msg->ack_id, status, MSG_SIZE(in_msg),
                      in_msg->len, nbytes, out_msg->len); */
            status = 0;
        }
    }

    fclose(ucafs_mod_fid);

    return 0;
}
