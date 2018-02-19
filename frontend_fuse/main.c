#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <stddef.h>

#include "internal.h"

char * volume_path = NULL;

static struct options {
	char * volume_path;
} options;

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }

static struct fuse_opt option_spec[] = {
	OPTION("--vol %s", volume_path),
	FUSE_OPT_END
};

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

	volume_path = options.volume_path;

    printf("Starting nexus-fuse at [%s]...\n", volume_path);
    return start_fuse(&args);
}
