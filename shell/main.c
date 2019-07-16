/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus.h>
#include <nexus_json.h>
#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_volume.h>

#include "handler.h"
#include "../backend_sgx/exports.h"

static const char * nexus_prog_version = "Nexus Admin Shell 0.1";

struct nexus_cmd {
    char * name;
    int (*handler)(int argc, char ** argv);
    char * desc;
};

int
init_main(int argc, char ** argv)
{
    /* For now we just do a default config */
    nexus_setup();

    return 0;
}


static int
export_rootkey_main(int argc, char ** argv)
{
    struct nexus_volume * volume = NULL;

    char * volume_path         = NULL;
    char * other_instance_path = NULL;
    char * rootkey_dest_path   = NULL;


    if (argc < 3) {
        printf("export_rootkey <volume_path> <other_instance_path> <rootkey_dest_path>\n");
        return -1;
    }


    volume_path = strndup(argv[1], NEXUS_PATH_MAX);
    other_instance_path = strndup(argv[2], NEXUS_PATH_MAX);
    rootkey_dest_path = strndup(argv[3], NEXUS_PATH_MAX);

    // 1 - load the volume
    volume = nexus_mount_volume(volume_path);

    if (volume == NULL) {
        log_error("nexus_mount_volume() FAILED\n");
        goto out_err;
    }


    if (sgx_backend_export_rootkey(rootkey_dest_path, other_instance_path, volume)) {
        log_error("sgx_backend_export_rootkey() FAILED\n");
        goto out_err;
    }


    nexus_free(volume_path);
    nexus_free(other_instance_path);
    nexus_free(rootkey_dest_path);

    return 0;

out_err:
    nexus_free(volume_path);
    nexus_free(other_instance_path);
    nexus_free(rootkey_dest_path);

    return -1;
}


static int
import_rootkey_main(int argc, char ** argv)
{
    char * rootkey_src_path = NULL;


    if (argc < 2) {
        printf("import_rootkey <rootkey_src_path>");
        return -1;
    }

    rootkey_src_path = strndup(argv[1], NEXUS_PATH_MAX);

    if (sgx_backend_import_rootkey(rootkey_src_path)) {
        log_error("sgx_backend_import_rootkey() FAILED\n");
        goto out_err;
    }

    nexus_free(rootkey_src_path);

    return 0;
out_err:
    nexus_free(rootkey_src_path);

    return -1;
}

extern int
create_volume_main(int argc, char ** argv);
extern int
delete_volume_main(int argc, char ** argv);
// extern int       ls_path_main(int argc, char ** argv);
extern int
create_file_main(int argc, char ** argv);

extern int
repl_volume_main(int argc, char ** argv);

extern int
cmd_volume_main(int argc, char ** argv);

int
filler_volume_main(int argc, char ** argv);


static struct nexus_cmd cmds[] = { { "init", init_main, "Initialize Nexus Environment" },
                                   { "create", create_volume_main, "Create a Nexus Volume" },
                                   { "delete", delete_volume_main, "Delete a Nexus Volume" },
                                   { "repl", repl_volume_main, "Shows the REPL command line" },
                                   { "cmd", cmd_volume_main, "Runs REPL command" },
                                   { "filler", filler_volume_main, "Prefills the volume line" },
                                   { "create_file", create_file_main, "Create a new file" },
                                   { "export_rootkey", export_rootkey_main, "Export the rootkey exchange message" },
                                   { "import_rootkey", import_rootkey_main, "Import the sealed rootkey into the config" },
                                   { 0, 0, 0 } };

void
usage(void)
{
    int i = 0;

    printf("%s\n", nexus_prog_version);
    printf("Usage: nexus <command> [args...]\n");
    printf("Commands:\n");

    while (cmds[i].name) {
        printf("\t%-17s -- %s\n", cmds[i].name, cmds[i].desc);
        i++;
    }

    return;
}

int
main(int argc, char ** argv)
{
    int i     = 0;
    int ret   = 0;
    int found = 0;

    if (argc < 2) {
        usage();
        exit(-1);
    }

    while (cmds[i].name) {

        if (strncmp(cmds[i].name, argv[1], 128) == 0) {

            found = 1;

            nexus_init();
            ret = cmds[i].handler(argc - 1, &argv[1]);
            nexus_deinit();

            break;
        }

        i++;
    }

    if (found == 0) {
        usage();
        exit(-1);
    }


    return ret;
}
