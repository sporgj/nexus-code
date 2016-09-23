#ifndef AFS_SGX_H
#define AFS_SGX_H

#include "afsx_hdr.h"

extern int LINUX_AFSX_connect(void);
extern int LINUX_AFSX_ping(void);
extern int UCAFS_ignore_dentry(struct dentry * dp, char ** dest);
/**
 * Creates a new file/dir in the dentry dp
 * @param dest is the encoded filename destination ptr
 * @param is_file is (AFSX_IS_DIR/AFSX_IS_FILE)
 * @param dp is the containing dentry
 * @return 0 on success
 */
extern int UCAFS_create(char ** dest, ucafs_entry_type type,
                        struct dentry * dp);
extern int UCAFS_remove(char ** dest, struct dentry * dp);
extern int UCAFS_rename(char ** dest, struct dentry * from_dp,
                        struct dentry * to_dp);
extern int UCAFS_find(char ** dest, char * fname, ucafs_entry_type type,
                      char * parent_dir);
extern int UCAFS_lookup(char ** dest, struct dentry * dp);
extern int UCAFS_store(struct vcache * avc, struct vrequest * areq);
extern int UCAFS_fetch(struct vcache * avc, struct vrequest * areq);
#endif
