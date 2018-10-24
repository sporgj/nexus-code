#include <stddef.h>

#include "nexus_fuse.h"


struct nexus_volume * nexus_fuse_volume = NULL;


char * volume_path = NULL;
char * mount_path  = NULL;

int
main(int argc, char * argv[])
{
    int ret = -1;

    if (argc < 3) {
        fprintf(stdout, "usage: %s <volume_path> [fuse options] <mountpath>\n", argv[0]);
        fflush(stdout);
        return -1;
    }


    {
        volume_path = strndup(argv[1], PATH_MAX);

        if (volume_path == NULL) {
            log_error("Could not get volume path\n");
            return -1;
        }

        mount_path = strndup(argv[argc - 1], PATH_MAX);

        if (mount_path == NULL) {
            nexus_free(volume_path);
            log_error("Could not get volume path\n");
            return -1;
        }
    }


    nexus_init();

    nexus_fuse_volume = nexus_mount_volume(volume_path);

    if (nexus_fuse_volume == NULL) {
        log_error("failed to mount '%s'\n", volume_path);
        goto out;
    }


    if (vfs_init()) {
        log_error("could not initialize the internal VFS system\n");
        goto out;
    }

    printf("Starting nexus-fuse at [%s] (pid=%d)...\n", mount_path, (int) getpid());

    argv[1] = argv[0];
    ret = start_fuse(argc - 1, &argv[1], true, mount_path);


out:
    vfs_deinit();

    // TODO handle nexus_deinit properly

    nexus_free(volume_path);
    nexus_free(mount_path);

    return ret;
}
