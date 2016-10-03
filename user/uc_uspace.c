#include "uc_uspace.h"
#include <string.h>

static sds main_dnode_fpath;

sds global_home_path;

sds global_repo_path;

bool global_env_is_afs;

void uc_set_afs_home(const char * path, const char * watched_dir, bool is_afs)
{
    global_env_is_afs = is_afs;

    global_home_path = sdsnew(path);

    if (watched_dir) {
        global_home_path = sdscat(global_home_path, "/");
        global_home_path = sdscat(global_home_path, watched_dir);
    }

    global_repo_path = sdsnew(path);
    global_repo_path = sdscat(global_repo_path, "/.afsx");

    main_dnode_fpath = sdsdup(global_repo_path);
    main_dnode_fpath = sdscat(main_dnode_fpath, "/");
    main_dnode_fpath = sdscat(main_dnode_fpath, "main.dnode");
}

sds uc_get_repo_path() {
    return sdsdup(global_repo_path);
}

sds uc_main_dnode_fpath() { return sdsdup(main_dnode_fpath); }

sds uc_get_dnode_path(const char * dnode_name)
{
    sds path = sdsdup(global_repo_path);
    path = sdscat(path, "/");
    path = sdscat(path, dnode_name);
    return path;
}

static sds __relpath(const char * path, bool parent)
{
    size_t len;
    // TODO let's assume the path sent to us has a valid prefix
    const char *ptr1 = path + strlen(global_home_path),
               *ptr2 = path + strlen(path);

    if (parent) {
        while (*ptr2 != '/' && ptr2 != ptr1) {
            ptr2--;
        }
    }

    len = ptr2 - ptr1;

    return len > 0 ? sdsnewlen(ptr1, len) : sdsnew("");
}

sds uc_get_relative_path(const char * path) { return __relpath(path, false); }

sds uc_get_relative_parentpath(const char * path)
{
    return __relpath(path, true);
}
