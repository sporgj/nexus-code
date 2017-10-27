#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>


#include "log.h"
#include "xdr.h"
#include "xdr_prototypes.h"
#include "rpc.h"
#include "afs.h"


#define UCAFS_MOD_FILE "/dev/ucafs_mod"

static FILE * ucafs_mod_fid = NULL;

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

#define XDROUT_DATALEN  64
#define XDROUT_TOTALLEN (XDROUT_DATALEN + sizeof(XDR) + sizeof(afs_op_msg_t))

/** we are going to have 3 buffers */
uint8_t in_buffer[UCAFS_DATA_BUFLEN];
uint8_t out_buffer[UCAFS_DATA_BUFLEN];
struct afs_op_msg in_rpc = {0};

static size_t    global_xfer_buflen = 0;
static uint8_t * global_xfer_addr   = NULL;





static int
connect_to_afs()
{
    
    /* Despite the misleading naming convention, these are actually local types */
    struct xdr_data  * x_data  = (struct xdr_data *)in_buffer;
    struct xdr_rsp   * x_rsp   = (struct xdr_rsp  *)out_buffer;

    struct afs_op_msg * in_msg  = &in_rpc;
    struct afs_op_msg * out_msg = &x_rsp->msg;

    XDR * xdr_in  = &x_data->xdrs;
    XDR * xdr_out = &x_rsp->xdrs;

    size_t nbytes = 0;
    int    len    = 0;
    int    status = 0;
    int    ret    = 0;
    int    fno    = 0;

    if (ucafs_mod_fid) {
        return 0;
    }

    ucafs_mod_fid = fopen(UCAFS_MOD_FILE, "rb+");
    
    if (ucafs_mod_fid == NULL) {
        log_error("opening '%s' failed", UCAFS_MOD_FILE);
        perror("Error: ");
        return -1;
    }

    fno = fileno(ucafs_mod_fid);

    /* set the memory map */
    ret = ioctl(fno, IOCTL_MMAP_SIZE, &global_xfer_buflen);
    
    if (ret != 0) {
        log_error("ioctl MMAP_SIZE failed");
        return -1;
    }

    /* mmap the xfer address to kernel memory */
    global_xfer_addr = mmap(NULL,
			    global_xfer_buflen,
			    PROT_READ | PROT_WRITE,
                            MAP_SHARED,
			    fno,
			    0);

    if (global_xfer_addr == (void *)-1) {
        log_error("mmap failed (size=%zu) :(", global_xfer_buflen);
        return -1;
    }

    log_debug("mmap %p for %zu bytes", global_xfer_addr, global_xfer_buflen);

    while (1) {
        nbytes = fread(in_msg, 1, sizeof(struct afs_op_msg), ucafs_mod_fid);

        if (nbytes != sizeof(struct afs_op_msg)) {
	    log_error("Invalid read size of %lu (expected %lu)\n", nbytes, sizeof(struct afs_op_msg));
	    return -1;
	}
	    
	/* read the data on the wire */
	nbytes = fread(x_data->data, 1, in_msg->len, ucafs_mod_fid);
	
	/* create our XDR data */
	xdrmem_create(xdr_in, (caddr_t)x_data->data, in_msg->len, XDR_DECODE);
	xdrmem_create(xdr_out, x_rsp->msg.payload,    PAGE_SIZE,   XDR_ENCODE);
	
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
            case AFS_OP_CHECKACL:
                status = rpc_checkacl(xdr_in, xdr_out);
                break;
            case AFS_OP_XFER_INIT:
                status = rpc_xfer_init(xdr_in, xdr_out);
                break;
            case AFS_OP_XFER_RUN:
                status = rpc_xfer_run(xdr_in, xdr_out);
                break;
            case AFS_OP_XFER_EXIT:
                status = rpc_xfer_exit(xdr_in, xdr_out);
                break;
            default:
                break;
	}

	/* send the response */
	nbytes = xdr_out->x_private - xdr_out->x_base;

	*out_msg = (struct afs_op_msg){.msg_id  = get_new_msg_id(),
				       .ack_id  = in_msg->msg_id,
				       .len     = nbytes,
				       .type    = in_msg->type,
				       .status  = status };

	len = sizeof(struct afs_op_msg) + out_msg->len;

	/* send the whole thing */
	nbytes = fwrite(out_msg, 1, len, ucafs_mod_fid);

	/*log_debug("{ uc_mod } type=%d id=%d status=%d in=(%zu, %d), "
	  "out=(%zu, %d)",
	  out_msg->type, out_msg->ack_id, status, MSG_SIZE(in_msg),
	  in_msg->len, nbytes, out_msg->len); */
	status = 0;
    }

    fclose(ucafs_mod_fid);

    return 0;
}







int
main(int argc, char ** argv)
{

    printf("Launching Nexus-AFS\n");

    log_debug("Connecting to AFS op channel\n");
    connect_to_afs();
    



#if 0
    /* send all the paths */
    for (size_t i = 0; i < global_supernode_count; i++) {
        sds path = sdsnew(global_supernode_paths[i]);

	path = sdscat(path, "/");
        path = sdscat(path, UCAFS_WATCH_DIR);
        
        if ((ret = ioctl(fno, IOCTL_ADD_PATH, path))) {
            log_error("ioctl ADD_PATH (%s) failed\n", path);
            sdsfree(path);
            return -1;
        }

        log_info("Added: %s", path);

	sdsfree(path);
    }
#endif




    return 0;

}
