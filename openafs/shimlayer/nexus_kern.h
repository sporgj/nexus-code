#pragma once
#include "nexus_header.h"

#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"

int
UCAFS_DISCONNECTED(void);

int
nexus_mod_init(void);

/* prototypes called from afs */
void
nexus_kern_ping(void);

int
nexus_dentry_path(const struct dentry * dentry, char ** dest);

int
nexus_vnode_path(const struct vcache * avc, char ** dest);

int
nexus_kern_create(struct vcache * avc,
                  char * name,
                  nexus_entry_type type,
                  char ** shadow_name);

int
nexus_kern_lookup(struct vcache * avc,
                  char * name,
                  nexus_entry_type type,
                  char ** shadow_name);

int
nexus_kern_remove(struct vcache * avc,
                  char * name,
                  nexus_entry_type type,
                  char ** shadow_name);

int
nexus_kern_filldir(char * parent_dir,
                   char * shdw_name,
                   nexus_entry_type type,
                   char ** real_name);

int
nexus_kern_rename(struct vcache * from_vnode,
                  char * oldname,
                  struct vcache * to_vnode,
                  char * newname,
                  char ** old_shadowname,
                  char ** new_shadowname);

int
nexus_kern_hardlink(struct dentry * olddp, struct dentry * newdp, char ** dest);

int
nexus_kern_symlink(struct dentry * dp, char * target, char ** dest);

int
nexus_kern_store(struct vcache * avc,
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
nexus_kern_fetch(struct afs_conn * tc,
                 struct rx_connection * rxconn,
                 struct osi_file * fp,
                 afs_size_t base,
                 struct dcache * adc,
                 struct vcache * avc,
                 afs_int32 size,
                 struct rx_call * acall,
                 char * path);

int
nexus_kern_storeacl(struct vcache * avc, AFSOpaque * acl_data);

int
nexus_kern_access(struct vcache * avc, afs_int32 rights);

char *
lookup_shdw_name(const char * shadow_name);

char *
lookup_path_name(const char * parent_path, const char * fname);

void
add_path_to_cache(const char * shadow_name,
                  const char * parent_path,
                  const char * fname);

void
remove_path_name(const char * parent_path, const char * fname);

void
remove_shdw_name(const char * shadow_name);

static inline nexus_entry_type
dentry_type(const struct dentry * dentry)
{
    if (d_is_file(dentry)) {
        return UC_FILE;
    } else if (d_is_dir(dentry)) {
        return UC_DIR;
    } else if (d_is_symlink(dentry)) {
        return UC_LINK;
    }

    return UC_ANY;
}

static inline nexus_entry_type
vnode_type(const struct vcache * vnode)
{
    if (vnode == NULL) {
        return UC_ANY;
    }

    switch (vType(vnode)) {
    case VREG:
        return UC_FILE;
    case VDIR:
        return UC_DIR;
    case VLNK:
        return UC_LINK;
    }

    return UC_ANY;
}
