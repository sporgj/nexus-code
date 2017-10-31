#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include "afs.h"
#include "log.h"
#include "rpc.h"
#include "xdr.h"
#include "xdr_prototypes.h"

#define NEXUS_MOD_FILE "/dev/nexus_mod"

static FILE * nexus_mod_fid = NULL;

static uint64_t msg_counter = 0;

static inline uint64_t
get_new_msg_id(void)
{
    return msg_counter++;
}

struct xdr_data {
    XDR     xdrs;
    uint8_t data[0];
};

struct xdr_rsp {
    XDR               xdrs;
    struct afs_op_msg msg;
};

#define XDROUT_DATALEN 64
#define XDROUT_TOTALLEN (XDROUT_DATALEN + sizeof(XDR) + sizeof(afs_op_msg_t))

/** we are going to have 3 buffers */
uint8_t           in_buffer[NEXUS_DATA_BUFLEN];
uint8_t           out_buffer[NEXUS_DATA_BUFLEN];
struct afs_op_msg in_rpc = { 0 };

/* the address and size of the global buffer */
static size_t    global_xfer_buflen = 0;

// TODO this is temporary
// For now, we can only watch files from alice and kdb
#define AFS_CELL_PATH "/afs/maatta.sgx/user"
static const char * global_volume_paths[]
    = { AFS_CELL_PATH "/kdb/nexus",   // user kdb
        AFS_CELL_PATH "/alice/nexus", // user alice
        NULL };

static int
send_nexus_volume_paths(int fno)
{
    int                         ret;
    int                         tlen;
    int                         len;
    struct nexus_watched_path * nx_path = NULL;
    const char *                path    = NULL;

    /* send all the paths */
    for (size_t i = 0; (global_volume_paths[i] != NULL); i++) {
        path = global_volume_paths[i];
        len  = strlen(path);

        tlen    = sizeof(struct nexus_watched_path) + len;
        nx_path = (struct nexus_watched_path *)calloc(1, tlen);
        if (nx_path == NULL) {
            log_error("allocation error");
            return -1;
        }

        // copy the string data into the struct
        nx_path->len = len;
        memcpy(nx_path->path, path, len);

        ret = ioctl(fno, IOCTL_ADD_PATH, nx_path);
        if (ret != 0) {
            log_error("ioctl ADD_PATH (%s) failed\n", path);
            free(nx_path);
            return -1;
        }

        log_info("Added: %s", path);
        free(nx_path);
    }

    return 0;
}

static uint8_t * global_xfer_addr   = NULL;

static int
connect_to_afs()
{

    /* Despite the misleading naming convention, these are actually local types
     */
    struct xdr_data * x_data = (struct xdr_data *)in_buffer;
    struct xdr_rsp *  x_rsp  = (struct xdr_rsp *)out_buffer;

    struct afs_op_msg * in_msg  = &in_rpc;
    struct afs_op_msg * out_msg = &x_rsp->msg;

    XDR * xdr_in  = &x_data->xdrs;
    XDR * xdr_out = &x_rsp->xdrs;

    size_t nbytes = 0;
    int    len    = 0;
    int    status = 0;
    int    ret    = 0;
    int    fno    = 0;

    if (nexus_mod_fid) {
        return 0;
    }

    nexus_mod_fid = fopen(NEXUS_MOD_FILE, "rb+");

    if (nexus_mod_fid == NULL) {
        log_error("opening '%s' failed", NEXUS_MOD_FILE);
        perror("Error: ");
        return -1;
    }

    fno = fileno(nexus_mod_fid);

    /* send the volume paths */
    if (send_nexus_volume_paths(fno)) {
        return -1;
    }

    /* set the memory map */
    ret = ioctl(fno, IOCTL_MMAP_SIZE, &global_xfer_buflen);

    if (ret != 0) {
        log_error("ioctl MMAP_SIZE failed");
        return -1;
    }

    /* mmap the xfer address to kernel memory */
    global_xfer_addr = mmap(
        NULL, global_xfer_buflen, PROT_READ | PROT_WRITE, MAP_SHARED, fno, 0);

    if (global_xfer_addr == (void *)-1) {
        log_error("mmap failed (size=%zu) :(", global_xfer_buflen);
        return -1;
    }

    log_debug("mmap %p for %zu bytes", global_xfer_addr, global_xfer_buflen);

    while (1) {
        nbytes = fread(in_msg, 1, sizeof(struct afs_op_msg), nexus_mod_fid);

        if (nbytes != sizeof(struct afs_op_msg)) {
            log_error("Invalid read size of %lu (expected %lu)\n",
                      nbytes,
                      sizeof(struct afs_op_msg));
            return -1;
        }

        /* read the data on the wire */
        nbytes = fread(x_data->data, 1, in_msg->len, nexus_mod_fid);

        /* create our XDR data */
        xdrmem_create(xdr_in, (caddr_t)x_data->data, in_msg->len, XDR_DECODE);
        xdrmem_create(xdr_out, x_rsp->msg.payload, PAGE_SIZE, XDR_ENCODE);

        /* dispatch to the corresponding function */

        switch (in_msg->type) {
        case AFS_OP_PING:
            status = rpc_ping(xdr_in, xdr_out);
            break;
        case AFS_OP_LOOKUP:
        case AFS_OP_FILLDIR:
        case AFS_OP_CREATE:
        case AFS_OP_REMOVE:
            status = rpc_dirops(in_msg->type, xdr_in, xdr_out);
            break;
        case AFS_OP_SYMLINK:
            status = rpc_symlink(xdr_in, xdr_out);
            break;
        case AFS_OP_HARDLINK:
            status = rpc_hardlink(xdr_in, xdr_out);
            break;
        case AFS_OP_RENAME:
            status = rpc_rename(xdr_in, xdr_out);
            break;
        case AFS_OP_STOREACL:
            status = rpc_storeacl(xdr_in, xdr_out);
            break;
        default:
            break;
        }

        /* send the response */
        nbytes = xdr_out->x_private - xdr_out->x_base;

        /* construct the message by writing over the buffer */
        *out_msg = (struct afs_op_msg){.msg_id = get_new_msg_id(),
                                       .ack_id = in_msg->msg_id,
                                       .len    = nbytes,
                                       .type   = in_msg->type,
                                       .status = status };

        len = sizeof(struct afs_op_msg) + out_msg->len;

        /* send the whole thing */
        nbytes = fwrite(out_msg, 1, len, nexus_mod_fid);

        /*log_debug("{ uc_mod } type=%d id=%d status=%d in=(%zu, %d), "
          "out=(%zu, %d)",
          out_msg->type, out_msg->ack_id, status, MSG_SIZE(in_msg),
          in_msg->len, nbytes, out_msg->len); */
        status = 0;
    }

    fclose(nexus_mod_fid);

    return 0;
}

int
main(int argc, char ** argv)
{

    printf("Launching Nexus-AFS\n");

    log_debug("Connecting to AFS op channel\n");
    if (connect_to_afs()) {
        return -1;
    }

    return 0;
}
