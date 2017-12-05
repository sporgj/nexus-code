#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <wordexp.h>

#include <nexus_log.h>

#include "afs.h"
#include "handler.h"


#define DEFAULT_VOLUME_PATH       "$HOME/nexus-volume"
#define DEFAULT_METADATA_PATH       DEFAULT_VOLUME_PATH"/metadata"
#define DEFAULT_DATAFOLDER_PATH     DEFAULT_VOLUME_PATH"/datafolder"

#define DEFAULT_VOL_KEY_FILENAME  "$HOME/.nexus/volume_key"
#define DEFAULT_PUB_KEY_FILENAME  "$HOME/.nexus/public_key"
#define DEFAULT_PRV_KEY_FILENAME  "$HOME/.nexus/private_key"

static char * metadata_dirpath   = NULL;
static char * datafolder_dirpath = NULL;

static char * vol_key_filename  = NULL;
static char * pub_key_filename  = NULL;
static char * prv_key_filename  = NULL;

static int cmd_line_metadata_dir   = 0;
static int cmd_line_datafolder_dir = 0;
static int cmd_line_prv_key        = 0;
static int cmd_line_pub_key        = 0;
static int cmd_line_vol_key        = 0;

static int 
set_defaults()
{
    wordexp_t metadata_path_exp;
    wordexp_t datafolder_path_exp;
    wordexp_t vol_key_filename_exp;
    wordexp_t pub_key_filename_exp;
    wordexp_t prv_key_filename_exp;

    wordexp(DEFAULT_METADATA_PATH, &metadata_path_exp, 0);
    wordexp(DEFAULT_DATAFOLDER_PATH, &datafolder_path_exp, 0);
    wordexp(DEFAULT_VOL_KEY_FILENAME, &vol_key_filename_exp, 0);
    wordexp(DEFAULT_PUB_KEY_FILENAME, &pub_key_filename_exp, 0);
    wordexp(DEFAULT_PRV_KEY_FILENAME, &prv_key_filename_exp, 0);

    metadata_dirpath   = strndup(metadata_path_exp.we_wordv[0], PATH_MAX);
    datafolder_dirpath = strndup(datafolder_path_exp.we_wordv[0], PATH_MAX);
    vol_key_filename   = strndup(vol_key_filename_exp.we_wordv[0], PATH_MAX);
    pub_key_filename   = strndup(pub_key_filename_exp.we_wordv[0], PATH_MAX);
    prv_key_filename   = strndup(prv_key_filename_exp.we_wordv[0], PATH_MAX);

    wordfree(&metadata_path_exp);
    wordfree(&datafolder_path_exp);
    wordfree(&vol_key_filename_exp);
    wordfree(&pub_key_filename_exp);
    wordfree(&prv_key_filename_exp);

    return 0;
}






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

	
	if (size == 0) {
	    log_error("Read of size (0). continuing...\n");
	    continue;
	} else if (size < 0) {
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





	ret = dispatch_nexus_command(cmd_buf, size, &resp_buf, (uint32_t *)&resp_size);

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




void
usage(void)
{
    printf("Usage: \n");
    return;
}

static struct option long_options[] = {
    { "metadata_dir", required_argument, &cmd_line_metadata_dir, 1 }, /* 0 */
    { "data_dir", required_argument, &cmd_line_datafolder_dir, 1 },   /* 1 */
    { "prv_key", required_argument, &cmd_line_prv_key, 1 },           /* 2 */
    { "pub_key", required_argument, &cmd_line_pub_key, 1 },           /* 3 */
    { "vol_key", required_argument, &cmd_line_vol_key, 1 },           /* 4 */
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

int
main(int argc, char ** argv)
{

    /* Setup default path strings with ENV expansions */
    set_defaults();

    
    /* Override defaults with command line arguments */
    {
 	int  opt_index = 0;
	char c = 0;
	
	
	while ((c = getopt_long(argc, argv, "h", long_options, &opt_index)) != -1) {
	    
	    switch (c) {
		case 0:
		    switch (opt_index) {
			case 0:
			    nexus_free(metadata_dirpath);
			    metadata_dirpath = optarg;
			    break;

			case 1:
			    nexus_free(datafolder_dirpath);
			    datafolder_dirpath = optarg;
			    break;

			case 2:
			    nexus_free(prv_key_filename);
			    prv_key_filename = optarg;
			    break;

			case 3:
			    nexus_free(pub_key_filename);
			    pub_key_filename = optarg;
			    break;

			case 4:
			    nexus_free(vol_key_filename);
			    vol_key_filename = optarg;
			    break;
			default:
			    break;
		    }
		    break;

		case 'h':
		default:
		    usage();
		    return -1;
	    }
	}
    }
    
    
    printf("Launching Nexus-AFS.\n");
    printf("\t data folder: %s\n", datafolder_dirpath);
    printf("\t    metadata: %s\n", metadata_dirpath);
    fflush(stdout);

    // initialize libnexus and mount the volume
    {
	int ret = -1;

	if (nexus_init()) {
	    log_error("could not initialize nexus");
	    return -1;
	}

        ret = nexus_mount_volume(metadata_dirpath,
                                 datafolder_dirpath,
                                 vol_key_filename,
                                 pub_key_filename,
                                 prv_key_filename);
	if (ret != 0) {
	    log_error("could not mount volume :(");
	    nexus_exit();
	    return -1;
	}
    }


    {
	int volume_fd   = 0;
	
	volume_fd = create_nexus_volume(datafolder_dirpath);
	
	if (volume_fd == -1) {
	    log_error("could not create volume\n");
	    return -1;
	}
	
	handle_afs_cmds(volume_fd);
    }
    
    return 0;
}
