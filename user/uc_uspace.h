#include <stdbool.h>

#include "third/sds.h"

/**
 * path to the default home directory
 */
extern sds global_home_path;

/** path to the default repo director.  home_path/.afsx */
extern sds global_repo_path;

extern bool global_env_is_afs;

/**
 * Sets the home path. Essentially, the directory where the metadata is stored
 */
void
uc_set_afs_home(const char * path, const char * watched_dir, bool is_afs);

sds
uc_get_repo_path();

sds
uc_main_dnode_fpath();

sds
uc_get_dnode_path(const char * fname);

sds
uc_get_relative_parentpath(const char * path);

sds
uc_get_relative_path(const char * path);
