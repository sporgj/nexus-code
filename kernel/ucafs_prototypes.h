#ifndef AFS_SGX_H
#define AFS_SGX_H

#include "ucafs_defs.h"

extern int
ucafs_connect(void);

extern int
ucafs_ping(void);

extern int
UCAFS_ignore_dentry(struct dentry * dp, char ** dest);

/**
 * Returns the full path to the vnode if it resides in a "watched"
 * directory
 * @param avc is the vnode to resole
 * @param dest is the pointer to hold the string. Free with kfree
 * @return 0 on success
 */
int
ucafs_vnode_path(struct vcache * avc, char ** dest);

/**
 * Creates a new file/dir in the directory
 * @param parent_vnode
 * @param name
 * @param type
 * @param shadow_name_dest
 */
int
ucafs_create(struct vcache * parent_vnode,
             char * name,
             ucafs_entry_type type,
             char ** shadow_name_dest);

int
ucafs_find(char * parent_path,
           char * shadow_name,
           ucafs_entry_type,
           char ** dest);

int
ucafs_lookup(struct vcache * parent_vnode,
             char * name,
             ucafs_entry_type type,
             char ** shadow_name_dest);

int
ucafs_lookup1(char * parent_path,
              char * plain_file_name,
              ucafs_entry_type type,
              char ** dest);

int
ucafs_remove2(struct vcache * vnode, char ** dest);

int
ucafs_remove1(struct vcache * parent_vnode,
              char * name,
              ucafs_entry_type type,
              char ** dest);

int
ucafs_remove(char * fpath, ucafs_entry_type type, char ** dest);

int
ucafs_rename(struct vcache * from_vnode,
             char * oldname,
             struct vcache * to_vnode,
             char * newname,
             char ** old_shadowname,
             char ** new_shadowname);

int
ucafs_rename2(char * dirpath,
              char * oldname,
              char * newname,
              ucafs_entry_type type,
              char ** dest);
extern int
UCAFS_lookup(char ** dest, struct dentry * dp);

int
ucafs_plain2code(char * parent_path,
                 char * plain_file_name,
                 ucafs_entry_type type,
                 char ** dest);

int ucafs_hardlink(struct dentry * olddp, struct dentry * newdp, char ** dest);

int ucafs_symlink(struct dentry *dp, char * target, char ** dest);

int
ucafs_store(struct vcache * avc, struct vrequest * areq, int sync);

int
ucafs_get(struct afs_conn * tc,
          struct rx_connection * rxconn,
          struct osi_file * fp,
          afs_size_t base,
          struct dcache * adc,
          struct vcache * avc,
          afs_int32 size,
          struct afs_FetchOutput * tsmall);

int
ucafs_verify(struct vcache * avc, char * path);

/* dnlc prototypes */
int
uc_silly_del(const char * key);

char *
uc_silly_get(const char * key);

int
uc_silly_add(const char * sillyname,
             const char * realname,
             const char * shadowname);

#endif
