#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <stddef.h>

#include "internal.h"


char * datastore_path = NULL;

struct nexus_volume * mounted_volume = NULL;

static struct options {
    int background_mode;
    char * volume_path;
} options;

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }

static struct fuse_opt option_spec[] = {
    OPTION("--vol %s", volume_path),
    OPTION("--bg", background_mode),
    FUSE_OPT_END
};

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

    asprintf(&datastore_path, "%s/%s", options.volume_path, root_path);

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
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) {
        log_error("parsing options failed\n");
        return -1;
    }

    if (options.volume_path == NULL) {
        printf("usage: %s [fuse options] --vol <volume_path> <mount_path>\n", argv[0]);
        fflush(stdout);
        return -1;
    }

    nexus_init();

    mounted_volume = nexus_mount_volume(options.volume_path);

    if (mounted_volume == NULL) {
        log_error("failed to mount '%s'\n", options.volume_path);
        return -1;
    }

    if (datastore_path == NULL) {
        log_error("did not initialize datastore path, check volume config\n");
        // TODO cleanup
        return -1;
    }

    printf("Starting nexus-fuse at [%s] (pid=%d)...\n",
           datastore_path, (int) getpid());

    // if not
    if (!options.background_mode) {
        fuse_opt_add_arg(&args, "-f");
    }

    return start_fuse(&args);
}

static struct nexus_datastore_impl fuse_datastore = {
    .name   = "FUSE",
    .open   = fuse_datastore_open,
    .close  = fuse_datastore_close
};

nexus_register_datastore(fuse_datastore);
