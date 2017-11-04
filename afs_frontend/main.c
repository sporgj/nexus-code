#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "afs.h"
#include "log.h"
#include "rpc.h"
#include "xdr.h"
#include "xdr_prototypes.h"

#define NEXUS_MOD_FILE "/dev/nexus"


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

// TODO this is temporary
// For now, we can only watch files from alice and kdb
#define AFS_CELL_PATH "/afs/maatta.sgx/user"
static const char * global_volume_paths = AFS_CELL_PATH "/alice/nexus";

/** we are going to have 3 buffers */
uint8_t           in_buffer[NEXUS_DATA_BUFLEN];
uint8_t           out_buffer[NEXUS_DATA_BUFLEN];
struct afs_op_msg in_rpc = { 0 };





static int
send_nexus_volume_paths(int fno)
{
    struct nexus_watched_path * cmd = NULL;

    len  = strlen(path);
	
    cmd_len    = sizeof(struct nexus_watched_path) + strlen(;
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

        log_debug("Added: %s", path);
        free(nx_path);
    }

    return 0;
}


int
handle_afs_command(uint8_t   * cmd_buf,
		   uint32_t    cmd_size,
		   uint8_t  ** resp_buf,
		   uint32_t  * resp_size)
{
    
    return 0;    
}

static int
connect_to_afs()
{

    struct epoll_event afs_evt;    

    int   afs_fd = 0;
    int epoll_fd = 0;

    int ret      = 0;

    
    

    epoll_fd = epoll_create1(0);

    if (epoll_fd == -1) {	
	perror("Could not create epoll instance:");
	return -1;
    }

    
    afs_fd = open(NEXUS_MOD_FILE, O_RDWR);

    if (afs_fd == -1) {
        log_error("opening '%s' failed", NEXUS_MOD_FILE);
        perror("Error: ");
        return -1;
    }

    /* send the volume paths */
    if (send_nexus_volume_paths(afs_fd)) {
        return -1;
    }


#if 0
    /* set the memory map */
    ret = ioctl(fd, IOCTL_MMAP_SIZE, &global_xfer_buflen);

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
#endif

    

    afs_evt.events  = EPOLLIN;
    afs_evt.data.fd = afs_fd;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, afs_fd, &afs_evt);

    if (ret == -1) {
	log_error("Could not add afs fd to epoll instance\n");
	return -1;
    }
    
    while (1) {
	struct epoll_event event;

	uint8_t * cmd_buf  = NULL;
	uint8_t * resp_buf = NULL;

	int resp_size = 0;

	int num_fds = 0;
	int size    = 0;
	
	num_fds = epoll_wait(epoll_fd, &event, 1, -1);

	if (num_fds == -1) {
	    log_error("epoll wait returned error (%d)\n", num_fds);
	    perror("Error: ");
	}
	
	if (event.data.fd != afs_fd) {
	    log_error("epoll returned an invalid FD (%d)\n", event.data.fd);
	    return -1;
	}

	
	size = read(afs_fd, NULL, 0);

	if (size <= 0) {
	    log_error("Invalid read size from AFS module (size=%d)\n", size);
	    return -1;
	}

	cmd_buf = calloc(1, size);

	if (cmd_buf == NULL) {
	    log_error("Could not allocate command buffer of size (%d)\n", size);
	    return -1;
	}
	
	ret = read(afs_fd, cmd_buf, size);
	
	if (ret != size) {
	    log_error("Could not read command from AFS module (ret = %d)\n", ret);
	    return -1;
	}


	printf("AFS Command = %s\n", cmd_buf);

	return -1;


	
	ret = handle_afs_command(cmd_buf, size, &resp_buf, (uint32_t *)&resp_size);

	if (ret == -1) {
	    log_error("Error handling AFS command\n");
	    return -1;
	}
	
	ret = write(afs_fd, resp_buf, resp_size);

	if (ret != resp_size) {
	    log_error("Error writing response to AFS module\n");
	}
	
	free(resp_buf);

#if 0
	
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

#endif
    }

    close(afs_fd);
    
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
