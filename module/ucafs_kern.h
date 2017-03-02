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

// returns true if the fname is prefixed with .md
static inline int is_md_file(const char * fname, int count)
{
    int min_len = UC_PREFIX_LEN(UC_METADATA_PREFIX);
    // let's check if the path equals
    if (count >= min_len && memcmp(fname, UC_METADATA_PREFIX, min_len) == 0) {
        return 1;
    }

    return 0;
}

static inline ucafs_entry_type
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

static inline ucafs_entry_type
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
