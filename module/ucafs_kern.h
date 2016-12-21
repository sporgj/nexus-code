#pragma once
#include "afs/ucafs_header.h"

int
ucafs_mod_init(void);

/* prototypes called from afs */
void
ucafs_kern_ping(void);

int
ucafs_dentry_path(const struct dentry * dentry, char ** dest);

inline int
ucafs_vnode_path(const struct vcache * avc, char ** dest);

int
ucafs_kern_create(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name);

int
ucafs_kern_lookup(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name);

int
ucafs_kern_remove(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name);

int
ucafs_kern_filldir(char * parent_dir,
                   char * shdw_name,
                   ucafs_entry_type type,
                   char ** real_name);

int
ucafs_kern_symlink(char * parent_dir,
                   char * real_name,
                   ucafs_entry_type type,
                   char ** shadow_name);

int
ucafs_kern_hardlink(char * parent_dir,
                    char * real_name,
                    ucafs_entry_type type,
                    char ** shadow_name);

int
ucafs_kern_rename(struct vcache * from_dir,
                  char * from_name,
                  struct vcache * to_dir,
                  char * to_name,
                  char ** old_shadowname,
                  char ** new_shadowname);
