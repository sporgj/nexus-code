#include <string>
#include <cstring>

#include "uspace.h"
#include "types.h"

using std::string;

const char * global_afs_home_path = nullptr;

/** path to the default repo director.  home_path/.afsx */
const char * global_afs_repo_path = nullptr;

const char * global_watched_dir = nullptr;

bool global_env_is_afs = true;

void uspace_set_afs_home(const char * path, const char * watched_dir,
                         bool is_afs)
{
    if (global_afs_home_path) {
        free((void *)global_afs_home_path);
        free((void *)global_afs_repo_path);
    }

    string temp_str(path);

    global_afs_home_path = strdup(temp_str.c_str());

    if (watched_dir) {
        global_watched_dir = strdup(watched_dir);
    }

    temp_str += "/";
    temp_str += DEFAULT_REPO_DIRNAME;

    global_afs_repo_path = strdup(temp_str.c_str());
    global_env_is_afs = is_afs;
}

string * uspace_get_repo_path() { return new string(global_afs_repo_path); }

/**
 * returns a new[] path for the default directory.
 * Please free with delete[]
 */
string * uspace_main_dnode_fpath()
{
    string * rv_str = uspace_get_repo_path();
    rv_str->operator+=('/');
    rv_str->operator+=(DEFAULT_DNODE_FNAME);

    return rv_str;
}

void uspace_get_relpath_c(const char * path, char ** rv)
{
    // XXX next time, add watched folders to make sure we load the necessary
    // dnode object
    const char * ptr = path + strlen(global_afs_home_path);

    if (global_watched_dir) {
        ptr += strlen(global_watched_dir) + 1;
    }

    if (*ptr != '\0') {
        ptr++;
    }

    *rv = strdup(ptr);
}

string * uspace_make_dnode_fpath(const char * fname)
{
    string * rv = uspace_get_repo_path();
    rv->operator+=("/");
    rv->operator+=(fname);
    return rv;
}

string * uspace_make_fbox_fpath(const char * fname)
{
    return uspace_make_dnode_fpath(fname);
}
