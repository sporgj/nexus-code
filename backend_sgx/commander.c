/**
 * This file implements the Linux domain socket handler
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <pthread.h>


#include "internal.h"


#define DEFAULT_SOCKET_DIRPATH  "/tmp/.nexus-socks"

#define DEFAULT_SOCKET_BUFSIZE  1024


struct thread_info {
    struct sgx_backend  * backend;

    size_t                commands_received;
} socket_thread_info;


static struct sockaddr_un       socket_uds;

static int                      socket_fd;

static uint8_t                  socket_buf[DEFAULT_SOCKET_BUFSIZE];

static char *                   socket_fpath;

static pthread_t                socket_thread;


static int
__check_socket_directory(const char * dir)
{
    struct stat st;

    int ret = -1;


    if (stat(dir, &st)) {
        nexus_printf("Creating sockets directory: %s\n", dir);

        ret = mkdir(dir, 0770);

        if ((ret == -1) && (errno != EEXIST)) {
            log_error("could not create directory: %s\n", dir);
            return -1;
        }
    }

    return 0;
}


static int
__create_socket(const char * dir)
{
    int len = -1;

    socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("__create_socket:");
        return -1;
    }

    // create the socket fpath
    socket_fpath = tempnam(dir, NULL);
    if (socket_fpath == NULL) {
        log_error("tempnam() FAILED\n");
        goto out_err;
    }

    // initialize the socket structure
    memset(&socket_uds, 0, sizeof(socket_uds));
    socket_uds.sun_family = AF_UNIX;
    strncpy(socket_uds.sun_path, socket_fpath, PATH_MAX);

    // bind it to the file
    len = offsetof(struct sockaddr_un, sun_path) + strlen(socket_fpath);
    if (bind(socket_fd, (struct sockaddr *)&socket_uds, len) < 0) {
        log_error("binding socket to file (%s) FAILED\n", socket_fpath);
        perror("bind");
        goto out_err;
    }

    return 0;

out_err:
    close(socket_fd);

    if (socket_fpath) {
        nexus_free(socket_fpath);
    }

    return -1;
}


static void *
__commander_loop(void * backend_ptr)
{
    int n = -1;

loop:
    n = recv(socket_fd, socket_buf, sizeof(socket_buf), 0);

    if (n < 0) {
        log_error("recv failed\n");
        perror("recv:");
        goto out;
    }

    // TODO process buffer
    nexus_printf("heheh, commander just got shit\n");

    goto loop;

out:
    pthread_exit(NULL);
}

static int
__launch_commander_thread(struct sgx_backend * backend)
{
    memset(&socket_thread_info, 0, sizeof(struct thread_info));

    socket_thread_info.backend = backend;

    if (pthread_create(&socket_thread, NULL, __commander_loop, &socket_thread_info)) {
        log_error("pthread_create FAILED\n");
        perror("pthread_create");
        return -1;
    }

    return 0;
}

int
commander_create(struct sgx_backend * sgx_backend)
{
    char * dir = DEFAULT_SOCKET_DIRPATH;

    if (__check_socket_directory(dir)) {
        log_error("__check_socket_directory() FAILED\n");
        return -1;
    }

    if (__create_socket(dir)) {
        log_error("__create_socket() FAILED\n");
        return -1;
    }

    if (__launch_commander_thread(sgx_backend)) {
        log_error("__launch_commander_thread FAILED\n");
        return -1;
    }

    nexus_printf("Launched commander: %s\n", socket_fpath);

    return 0;
}

void
commander_destroy(struct sgx_backend * sgx_backend)
{
    if (socket_fd) {
        close(socket_fd);
    }

    if (socket_fpath) {
        nexus_free(socket_fpath);
    }
}
