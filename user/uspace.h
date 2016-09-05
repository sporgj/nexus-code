#include <string>
using std::string;

extern const char * gbl_temp_dnode_path;

/**
 * path to the default home directory
 */
extern const char * global_afs_home_path;

/** path to the default repo director.  home_path/.afsx */
extern const char * global_afs_repo_path;

void set_global_afs_home_path(const char * path);
string * get_default_repo_path();
string * get_default_dnode_fpath();

inline string * make_dnode_fpath(const char * fname) {
    string * rv = get_default_repo_path();
    rv->operator+=("/");
    rv->operator+=(fname);
    return rv;
}
