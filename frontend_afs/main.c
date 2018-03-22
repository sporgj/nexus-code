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

#include "internal.h"


#define DEFAULT_VOLUME_PATH       "$HOME/nexus-volume"

struct nexus_volume * mounted_volume = NULL;
static char         * volume_path    = NULL;


char * datastore_path    = NULL;
size_t datastore_pathlen = 0;


static int nexus_fd  = -1; // used for communicating with the kernel (mmap)
static int volume_fd = -1;


uint8_t * global_databuf_addr = NULL;
size_t    global_databuf_size = NEXUS_DATABUF_SIZE;



static uint8_t *
__generic_error_message(uint32_t * rsp_size)
{
    static const char generic_err_rsp_str[] = "\"code\": -1";

    *rsp_size = strnlen(generic_err_rsp_str, PATH_MAX) + 1;
    return (uint8_t *)strndup(generic_err_rsp_str, *rsp_size);
}


static int
attach_volume_datastore(char * path)
{
    nexus_fd = open(NEXUS_DEVICE, O_RDWR);

    if (nexus_fd == -1) {
	log_error("could not open Nexus Device file (%s)\n", NEXUS_DEVICE);
	return -1;
    }

    volume_fd = ioctl(nexus_fd, NEXUS_IOCTL_CREATE_VOLUME, path);

    if (volume_fd == -1) {
	log_error("Could not create Nexus Volume (%s)\n", path);
	return -1;
    }

    return volume_fd;
}

static void *
afs_datastore_open(nexus_json_obj_t cfg)
{
    char * root_datastore_path = NULL;

    int    ret = 0;

    ret = nexus_json_get_string(cfg, "root_path", &root_datastore_path);

    if (ret == -1) {
        log_error("Invalid AFS datastore config. Missing root_path\n");
        return NULL;
    }


    {
        char * fullpath = get_current_dir_name();
        char * tmp_path = NULL;

        asprintf(&tmp_path, "%s/%s", fullpath, root_datastore_path);

        datastore_path = realpath(tmp_path, NULL);

        nexus_free(fullpath);
        nexus_free(tmp_path);
    }


    volume_fd = attach_volume_datastore(datastore_path);

    if (volume_fd == -1) {
        nexus_free(datastore_path);

        log_error("could not attach volume\n");
        return NULL;
    }

    datastore_pathlen = strnlen(datastore_path, PATH_MAX);

    return datastore_path;
}

static int
afs_datastore_close(void * priv_data)
{
    // TODO call remove from afs & free datastore_path
    // nexus_free(priv_data);

    return 0;
}



static int
handle_afs_cmds(int volume_fd)
{

    struct epoll_event afs_evt;

    int epoll_fd = 0;

    int ret      = 0;

    /* mmap the xfer address to kernel memory */
    global_databuf_addr = mmap(NULL,
                               global_databuf_size,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED,
                               nexus_fd,
                               0);

    if (global_databuf_addr == (void *)-1) {
        log_error("mmap failed (size=%zu) :(", global_databuf_size);
        return -1;
    }


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
            resp_buf = __generic_error_message((uint32_t *) &resp_size);
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
usage(char * prog)
{
    printf("Usage: %s volume_path\n", prog);
    return;
}


int
main(int argc, char ** argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    volume_path = strndup(argv[1], PATH_MAX);
    if (volume_path == NULL) {
        log_error("could not get volume_path\n");
        return -1;
    }

    printf("Launching Nexus-AFS.\n");

    // initialize libnexus and mount the volume
    {
        if (nexus_init()) {
            log_error("could not initialize nexus");
            return -1;
        }

        mounted_volume = nexus_mount_volume(volume_path);
	if (mounted_volume == NULL) {
            log_error("could not mount volume :(");
            return -1;
        }
    }

    if (volume_fd == -1) {
        log_error("the volume has not been mounted\n");
        return -1;
    }

    printf("Started %s at: %s\n", argv[0], datastore_path);
    fflush(stdout);

    handle_afs_cmds(volume_fd);

    return 0;
}

static struct nexus_datastore_impl afs_datastore = {
    .name   = "AFS",
    .open   = afs_datastore_open,
    .close  = afs_datastore_close
};

nexus_register_datastore(afs_datastore);
