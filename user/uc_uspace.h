#include <stdbool.h>

#include "third/sds.h"

#include "uc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SUPERNODE_PATHS 20

/**
 * path to the default home directory
 */
extern sds global_home_path;

/** path to the default repo director.  home_path/.afsx */
extern sds global_repo_path;

extern bool global_env_is_afs;

extern shadow_t uc_root_dirnode_shadow_name;

extern char * global_supernode_paths[MAX_SUPERNODE_PATHS];

extern size_t global_supernode_count;

extern supernode_t * global_supernode_object;

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

/**
 * Derives the relative path with respect to the watch folder
 * @param path is the full path
 * @param is_dirpath if the path passed is the path to a parent folder
 * @return the relative path, NULL if the prefix doesn't match the
 * path to the watch folder
 */
sds
uc_derive_relpath(const char * fullpath, bool is_dirpath);


int metadata_init();
void metadata_exit();

void dcache_init();
void dcache_exit();

int ucafs_init_uspace();
int ucafs_exit_uspace();

int ucafs_init_vfs();
int ucafs_exit_vfs();

int ucafs_init_enclave();

int
vfs_mount(const char * path);

int
ucafs_login(const char * user_root_path);

sds
ucafs_supernode_path(const char * root_path);

sds
ucafs_metadata_path(const char * root_path, const char * meta_fname);

int
ucafs_launch(const char * mount_file_path);
#ifdef __cplusplus
}
#endif
