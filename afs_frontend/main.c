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



// TODO this is temporary
// For now, we can only watch files from alice and kdb
#define AFS_CELL_PATH "/afs/maatta.sgx/user"





static int
create_nexus_volume(char * path)
{
    int  nexus_fd = 0;
    int volume_fd = 0;

    nexus_fd = open(NEXUS_DEVICE, O_RDWR);
    
    if (nexus_fd == -1) {
	log_error("could not open Nexus Device file (%s)\n", NEXUS_DEVICE);
	return -1;
    }


    volume_fd = ioctl(nexus_fd, NEXUS_IOCTL_CREATE_VOLUME, path);

    close(nexus_fd);
    
    if (volume_fd == -1) {
	log_error("Could not create Nexus Volume (%s)\n", path);
	return -1;
    }
    
    return volume_fd;
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
handle_afs_cmds(int volume_fd)
{

    struct epoll_event afs_evt;    

    int epoll_fd = 0;

    int ret      = 0;

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
   
    epoll_fd = epoll_create1(0);

    if (epoll_fd == -1) {	
	perror("Could not create epoll instance:");
	return -1;
    }    

    afs_evt.events  = EPOLLIN;
    afs_evt.data.fd = volume_fd;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, volume_fd, &afs_evt);

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
	
	if (event.data.fd != volume_fd) {
	    log_error("epoll returned an invalid FD (%d)\n", event.data.fd);
	    return -1;
	}

	
	size = read(volume_fd, NULL, 0);

	if (size <= 0) {
	    log_error("Invalid read size from AFS module (size=%d)\n", size);
	    return -1;
	}

	cmd_buf = calloc(1, size);

	if (cmd_buf == NULL) {
	    log_error("Could not allocate command buffer of size (%d)\n", size);
	    return -1;
	}
	
	ret = read(volume_fd, cmd_buf, size);
	
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
	
	ret = write(volume_fd, resp_buf, resp_size);

	if (ret != resp_size) {
	    log_error("Error writing response to AFS module\n");
	}
	
	free(resp_buf);
    }

    close(volume_fd);
    
    return 0;
}

int
main(int argc, char ** argv)
{
    char * volume_path = NULL;
    int    volume_fd   = 0;
    
    if (argc < 2) {
	printf("./nexus-afs <volume-path>\n");
	exit(-1);
    }

    volume_path = argv[1];
    
    printf("Launching Nexus-AFS on Volume %s\n", volume_path);


    volume_fd = create_nexus_volume(volume_path);
    
    if (volume_fd == -1) {
	log_error("could not create volume\n");
	return -1;
    }

    handle_afs_cmds(volume_fd);
    
    return 0;
}
