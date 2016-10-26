#ifndef AFS_SGX_H
#define AFS_SGX_H

#include "ucafs_defs.h"

extern int
LINUX_AFSX_connect(void);

extern int
LINUX_AFSX_ping(void);

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
 * Creates a new file/dir in the dentry dp
 * @param dest is the encoded filename destination ptr
 * @param is_file is (AFSX_IS_DIR/AFSX_IS_FILE)
 * @param dp is the containing dentry
 * @return 0 on success
 */
extern int
UCAFS_create(char ** dest, ucafs_entry_type type, struct dentry * dp);

extern int
UCAFS_remove(char ** dest, struct dentry * dp);

int
ucafs_remove2(char * parent_path,
              char * file_name,
              ucafs_entry_type type,
              char ** dest);

extern int
UCAFS_rename(char ** dest, struct dentry * from_dp, struct dentry * to_dp);

int
ucafs_rename2(char * dirpath,
              char * oldname,
              char * newname,
              ucafs_entry_type type,
              char ** dest);

extern int
UCAFS_find(char ** dest,
           char * fname,
           ucafs_entry_type type,
           char * parent_dir);

extern int
UCAFS_lookup(char ** dest, struct dentry * dp);

extern int
UCAFS_hardlink(char ** dest, struct dentry * new_dp, struct dentry * to_dp);

extern int
UCAFS_store(struct vcache * avc, struct vrequest * areq);

extern int
UCAFS_fetch(struct vcache * avc, struct vrequest * areq);

extern int
UCAFS_get(struct afs_conn * tc,
          struct rx_connection * rxconn,
          struct osi_file * fp,
          afs_size_t base,
          struct dcache * adc,
          struct vcache * avc,
          afs_int32 size,
          struct afs_FetchOutput * tsmall);
#endif
