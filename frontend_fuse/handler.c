#include "internal.h"

static char *
__make_fullpath(const char * dirpath, const char * nexus_name)
{
    char * fullpath = NULL;

    int ret = -1;

    if (dirpath[0] == '\0') {
        ret = asprintf(&fullpath, "%s/%s", datastore_path, nexus_name);
    } else {
        ret = asprintf(&fullpath, "%s/%s/%s", datastore_path, dirpath, nexus_name);
    }

    if (ret <= 0) {
        log_error("error encoding path (%s)\n", dirpath);
        abort();
    }

    return fullpath;
}

static void
__get_nexuspath(const char * filepath, char ** dirpath, char ** filename)
{
    char * fname = NULL;

    const char * nexus_abspath = filepath + datastore_pathlen;

    fname = strrchr(nexus_abspath, '/');

    if (fname == NULL) {
        *filename = strndup(nexus_abspath, PATH_MAX);
        *dirpath = strndup("", PATH_MAX);
    } else {
        *filename = strndup(fname + 1, PATH_MAX);
        *dirpath = strndup(nexus_abspath, (int)(fname - nexus_abspath));
    }
}

int
handle_create(const char * path, nexus_dirent_type_t type, char ** nexus_fullpath)
{
    char * dirpath = NULL;
    char * fname   = NULL;

    char * nexus_name = NULL;

    int ret = -1;

    __get_nexuspath(path, &dirpath, &fname);

    ret = nexus_fs_touch(mounted_volume, dirpath, fname, type, &nexus_name);

    if (ret != 0) {
        log_error("creating %s FAILED\n", path);
        goto out;
    }

    printf("CREATE: dirpath=%s, fname=%s, nexus_name=%s\n", dirpath, fname, nexus_name);

    *nexus_fullpath = __make_fullpath(dirpath, nexus_name);

    ret = 0;
out:
    nexus_free(dirpath);
    nexus_free(fname);
    if (nexus_name) {
        nexus_free(nexus_name);
    }

    return ret;
}

int
handle_delete(const char * path, char ** nexus_fullpath)
{
    char * dirpath = NULL;
    char * fname   = NULL;

    char * nexus_name = NULL;

    int ret = -1;


    __get_nexuspath(path, &dirpath, &fname);

    ret = nexus_fs_remove(mounted_volume, dirpath, fname, &nexus_name);

    if (ret != 0) {
        log_error("creating %s FAILED\n", path);
        goto out;
    }

    printf("DELETE: dirpath=%s, fname=%s, nexus_name=%s\n", dirpath, fname, nexus_name);

    *nexus_fullpath = __make_fullpath(dirpath, nexus_name);

    ret = 0;
out:
    nexus_free(dirpath);
    nexus_free(fname);
    if (nexus_name) {
        nexus_free(nexus_name);
    }

    return ret;
}

int
handle_lookup(const char * path, char ** nexus_fullpath)
{
    char * dirpath = NULL;
    char * fname   = NULL;

    char * nexus_name = NULL;

    int ret = -1;


    if (path[0] == '/' && path[1] == '\0') {
        *nexus_fullpath = __make_fullpath("", "");
        return 0;
    }

    __get_nexuspath(path, &dirpath, &fname);

    ret = nexus_fs_lookup(mounted_volume, dirpath, fname, &nexus_name);

    if (ret != 0) {
        log_error("creating %s FAILED\n", path);
        goto out;
    }

    printf("LOOKUP: dirpath=%s, fname=%s, nexus_name=%s\n", dirpath, fname, nexus_name);

    *nexus_fullpath = __make_fullpath(dirpath, nexus_name);

    ret = 0;
out:
    nexus_free(dirpath);
    nexus_free(fname);
    if (nexus_name) {
        nexus_free(nexus_name);
    }

    return ret;
}

int
handle_filldir(const char * path, const char * name, char ** nexus_name)
{
    int ret = -1;

    char * nexus_abspath = (char *)path + datastore_pathlen;

    ret = nexus_fs_filldir(mounted_volume, nexus_abspath, (char *)name, nexus_name);

    if (ret != 0) {
        log_error("creating %s FAILED\n", nexus_abspath);
        return -1;
    }

    printf("FILLDIR: dirpath=%s, fname=%s, nexus_name=%s\n", nexus_abspath, name, *nexus_name);

    return 0;
}
