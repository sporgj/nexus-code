#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <pthread.h>

#include <nexus.h>
#include <nexus_util.h>

#include "../backend_sgx/exports.h"

#include "nexus_fuse.h"


#define DEFAULT_SOCKET_FILEPATH "/tmp/nxs-socks-XXXXXX"

#define DEFAULT_SOCKET_BUFSIZE  1024


struct sock_command {
    char * name;
    int (*handler)(void);
    char * desc;
};

struct thread_info {
    size_t                commands_received;
} socket_thread_info;


static struct sock_command      cmds[];


static struct sockaddr_un       socket_uds;

static int                      socket_fd;

static uint8_t                  socket_buf[DEFAULT_SOCKET_BUFSIZE];

static char *                   socket_fpath;

static pthread_t                socket_thread;


static int
__create_socket(const char * fullpath)
{
    int len = -1;
    int temp_fd = -1;

    socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("__create_socket:");
        return -1;
    }

    // create the socket fpath
    socket_fpath = strndup(fullpath, 1024);
    temp_fd = mkstemp(socket_fpath);
    if (temp_fd == -1) {
        log_error("mkstemp(%s) FAILED\n", socket_fpath);
        perror("mkstemp");
        goto out_err;
    }

    close(temp_fd);
    unlink(socket_fpath);

    // initialize the socket structure
    memset(&socket_uds, 0, sizeof(socket_uds));
    socket_uds.sun_family = AF_UNIX;
    strncpy(socket_uds.sun_path, socket_fpath, sizeof(socket_uds.sun_path));

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
    close(temp_fd);

    if (socket_fpath) {
        nexus_free(socket_fpath);
    }

    return -1;
}


static int
__enable_batching()
{
    if (sgx_backend_batch_mode_start(nexus_fuse_volume)) {
        log_error("sgx_backend_batch_mode_start FAILED\n");
        return -1;
    }

    nexus_printf("BATCH MODE ENABLED\n");

    return 0;
}

static int
__disable_batching()
{
    if (sgx_backend_batch_mode_finish(nexus_fuse_volume)) {
        log_error("sgx_backend_batch_mode_finish FAILED\n");
        return -1;
    }

    nexus_printf("BATCH MODE DISABLED\n");

    return 0;
}

static int
__flush_batching()
{
    if (sgx_backend_batch_mode_commit(nexus_fuse_volume)) {
        log_error("sgx_backend_batch_mode_commit FAILED\n");
        return -1;
    }

    nexus_printf("BATCH MODE FLUSHED\n");

    return 0;
}

static int
__help()
{
    for (size_t i = 0; cmds[i].name; i++) {
        // TODO
    }

    return 0;
}

static struct sock_command cmds[]
    = { { "enable_batching", __enable_batching, "enables batch mode" },
        { "disable_batching", __disable_batching, "disables batch mode" },
        { "flush_batches", __flush_batching, "flushes batched buffers" },
        { "help", __help, "help menu" },
        { NULL, NULL, NULL }};

static void *
__commander_loop()
{
    int n = -1;

    bool found;

loop:
    found = false;
    n = recv(socket_fd, socket_buf, sizeof(socket_buf), 0);

    if (n < 0) {
        log_error("recv failed\n");
        perror("recv:");
        goto out;
    }

    for (size_t i = 0; cmds[i].name; i++) {
        if (strncmp(cmds[i].name, (char *)socket_buf, strnlen(cmds[i].name, 1024)) == 0) {
            // TODO handle return value
            cmds[i].handler();
            found = true;
            break;
        }
    }

    if (found == false) {
        nexus_printf("UNKNOWN COMMAND: %s\n", (char *)socket_buf);
        fflush(stdout);
    }

    goto loop;

out:
    pthread_exit(NULL);
}

static int
__launch_commander_thread()
{
    memset(&socket_thread_info, 0, sizeof(struct thread_info));

    if (pthread_create(&socket_thread, NULL, __commander_loop, &socket_thread_info)) {
        log_error("pthread_create FAILED\n");
        perror("pthread_create");
        return -1;
    }

    return 0;
}

int
commander_init()
{
    if (__create_socket(DEFAULT_SOCKET_FILEPATH)) {
        log_error("__create_socket() FAILED\n");
        return -1;
    }

    if (__launch_commander_thread()) {
        log_error("__launch_commander_thread FAILED\n");
        return -1;
    }

    nexus_printf("Launched commander: %s\n", socket_fpath);

    return 0;
}

void
commander_destroy()
{
    if (socket_fd) {
        close(socket_fd);
    }

    if (socket_fpath) {
        nexus_free(socket_fpath);
    }
}
