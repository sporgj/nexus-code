#include "uc_uspace.h"
#include <string.h>

static sds main_dnode_fpath;

sds global_home_path;

sds global_repo_path;

bool global_env_is_afs;

shadow_t uc_root_dirnode_shadow_name = {0};

void uc_set_afs_home(const char * path, const char * watched_dir, bool is_afs)
{
    global_env_is_afs = is_afs;

    global_home_path = sdsnew(path);
    global_home_path = sdscat(global_home_path, "/");

    if (watched_dir) {
        global_home_path = sdscat(global_home_path, watched_dir);
        global_home_path = sdscat(global_home_path, "/");
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
    int len, temp = strlen(global_home_path);
    const char * ptr1 = path, * ptr2 = global_home_path;

    while (*ptr1 == *ptr2 && *ptr2 != '\0' && *ptr1 != '\0' && temp > 0) {
        ptr1++;
        ptr2++;
        temp--;
    }

    // XXX FIXME very very stupid. We know the length of the home
    // path doesn't change. I'm just keeping this here not to 
    // forget in a future fix
    if (*ptr2 == '/') {
        temp--;
    }

    if (temp != 0) {
        return NULL;
    }

    ptr2 = path + strlen(path);

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
