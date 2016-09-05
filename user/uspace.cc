#include <string>
#include <cstring>

#include "uspace.h"
#include "types.h"

using std::string;

const char * global_afs_home_path = nullptr;

/** path to the default repo director.  home_path/.afsx */
const char * global_afs_repo_path = nullptr;

void set_global_afs_home_path(const char * path)
{
    if (global_afs_home_path) {
        free((void *)global_afs_home_path);
        free((void *)global_afs_repo_path);
    }

    string temp_str(path);

    global_afs_home_path = strdup(temp_str.c_str());

    temp_str += "/";
    temp_str += DEFAULT_REPO_DIRNAME;

    global_afs_repo_path = strdup(temp_str.c_str());
}

inline string * get_default_repo_path()
{
    return new string(global_afs_repo_path);
}

/**
 * returns a new[] path for the default directory.
 * Please free with delete[]
 */
string * get_default_dnode_fpath()
{
    string * rv_str = get_default_repo_path();
    rv_str->operator+=('/');
    rv_str->operator+=(DEFAULT_DNODE_FNAME);

    return rv_str;
}
