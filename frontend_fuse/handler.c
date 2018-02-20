#include "internal.h"

static void
split_path(const char * filepath, char ** dirpath, char ** filename)
{
    char * fname = NULL;

    fname = strrchr(filepath, '/');

    if (fname == NULL) {
        *filename = strndup(filepath, PATH_MAX);
        *dirpath = strndup(".", PATH_MAX);
    } else {
        *filename = strndup(fname + 1, PATH_MAX);
        *dirpath = strndup(filepath, (int)(fname - filepath));
    }
}

int
handle_create(const char * fullpath, nexus_dirent_type_t type)
{
    char * dirpath = NULL;
    char * fname   = NULL;

    char * nexus_name = NULL;

    int ret = -1;

    split_path(fullpath, &dirpath, &fname);

    ret = nexus_fs_touch(mounted_volume, dirpath, fname, type, &nexus_name);

    if (ret != 0) {
        log_error("creating %s FAILED\n", fullpath);
        return -1;
    }

    printf("dirpath=%s, fname=%s, nexus_name=%s\n", dirpath, fname, nexus_name);

    return 0;
}
