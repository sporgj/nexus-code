#pragma once

#include <stdbool.h>

#include "third/sds.h"

#include "uc_types.h"

#define MAX_SUPERNODE_PATHS 20

typedef struct {
    char * root_ucafs;
    char * pubkey;
    char * privkey;
    char * mounts[MAX_SUPERNODE_PATHS];
} ucafs_config_t;

extern char * global_supernode_paths[MAX_SUPERNODE_PATHS];

extern size_t global_supernode_count;

extern supernode_t * global_supernode_object;

struct dirnode;

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
ucafs_login(const char * user_root_path);

sds
ucafs_supernode_path(const char * root_path);

sds
ucafs_metadata_path(const char * root_path, const char * meta_fname);

int
ucafs_launch(const char * mount_file_path);
