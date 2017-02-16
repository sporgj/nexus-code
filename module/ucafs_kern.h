#pragma once
#include <linux/dcache.h>

#include "afs/ucafs_header.h"

#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"

int
UCAFS_DISCONNECTED(void);

int
ucafs_mod_init(void);

/* prototypes called from afs */
void
ucafs_kern_ping(void);

int
ucafs_dentry_path(const struct dentry * dentry, char ** dest);

int
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
ucafs_kern_rename(struct vcache * from_vnode,
                  char * oldname,
                  struct vcache * to_vnode,
                  char * newname,
                  char ** old_shadowname,
                  char ** new_shadowname);

int
ucafs_kern_hardlink(struct dentry * olddp, struct dentry * newdp, char ** dest);

int
ucafs_kern_symlink(struct dentry * dp, char * target, char ** dest);

int
ucafs_kern_store(struct vcache * avc,
                 struct dcache ** dclist,
                 afs_size_t bytes,
                 afs_hyper_t * anewDV,
                 int * doProcessFS,
                 struct AFSFetchStatus * OutStatus,
                 afs_uint32 nchunks,
                 int nomore,
                 struct rx_call * afs_call,
                 char * path,
                 int base,
                 struct storeOps * ops,
                 void * rock);

int
ucafs_kern_fetch(struct afs_conn * tc,
                 struct rx_connection * rxconn,
                 struct osi_file * fp,
                 afs_size_t base,
                 struct dcache * adc,
                 struct vcache * avc,
                 afs_int32 size,
                 struct rx_call * acall,
                 char * path);

int
ucafs_kern_storeacl(struct vcache * avc, AFSOpaque * acl_data);

int
ucafs_kern_access(struct vcache * avc, afs_int32 rights);
