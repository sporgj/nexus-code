#include <string>
using std::string;

extern const char * gbl_temp_dnode_path;

/**
 * path to the default home directory
 */
extern const char * global_afs_home_path;

/** path to the default repo director.  home_path/.afsx */
extern const char * global_afs_repo_path;

extern bool global_env_is_afs;

void uspace_set_afs_home(const char * path, const char * watched_dir,
                         bool is_afs);

string * uspace_get_repo_path();

string * uspace_main_dnode_fpath();

string * uspace_make_dnode_fpath(const char * fname);
string * uspace_make_fbox_fpath(const char * fname);

/**
 * Returns the relative path with respect to the home directory
 * @param path is the parh to the home directory
 */
void uspace_get_relpath_c(const char * path, char ** rv);
