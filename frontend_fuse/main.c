#include <stddef.h>

#include "internal.h"


char * volume_path = NULL;

/* this is where the raw data files will be served from */
char * datastore_path = NULL;

/* the currently running volume */
struct nexus_volume * mounted_volume = NULL;


static void *
fuse_datastore_open(nexus_json_obj_t cfg)
{
    char * root_path = NULL;
    int    ret = 0;

    ret = nexus_json_get_string(cfg, "root_path", &root_path);

    if (ret == -1) {
        log_error("Invalid FLAT datastore config. Missing root_path\n");
        return NULL;
    }

    asprintf(&datastore_path, "%s/%s", volume_path, root_path);

    return datastore_path;
}

static int
fuse_datastore_close(void * priv_data)
{
    // TODO call fuse to stop here
    // nexus_free(volume_path);

    return 0;
}

int
main(int argc, char * argv[])
{
    if (argc < 3) {
        fprintf(stdout, "usage: %s <volume_path> [fuse options] <mountpath>\n", argv[0]);
        fflush(stdout);
        return -1;
    }


    volume_path = strndup(argv[1], PATH_MAX);
    if (volume_path == NULL) {
        log_error("Could not get volume path\n");
        return -1;
    }

    nexus_init();

    mounted_volume = nexus_mount_volume(volume_path);

    if (mounted_volume == NULL) {
        log_error("failed to mount '%s'\n", volume_path);
        return -1;
    }

    if (datastore_path == NULL) {
        log_error("did not initialize datastore path, check volume config\n");
        // TODO cleanup
        return -1;
    }

    printf("Starting nexus-fuse at [%s] (pid=%d)...\n", datastore_path, (int) getpid());

    // TODO handle nexus_deinit properly

    argv[1] = argv[0];
    return start_fuse(argc - 1, &argv[1], datastore_path);
}

static struct nexus_datastore_impl fuse_datastore = {
    .name   = "FUSE",
    .open   = fuse_datastore_open,
    .close  = fuse_datastore_close
};

nexus_register_datastore(fuse_datastore);
