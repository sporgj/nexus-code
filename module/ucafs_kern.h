#pragma once
#include "afs/ucafs_header.h"

int ucafs_mod_init(void);

/* prototypes called from afs */
void ucafs_kern_ping(void);

int
ucafs_dentry_path(const struct dentry * dentry, char ** dest);

inline int
ucafs_vnode_path(const struct vcache * avc, char ** dest);

int
ucafs_kern_create(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name);
