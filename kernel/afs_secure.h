#ifndef AFS_SGX_H
#define AFS_SGX_H

#ifndef AFSX_FNAME_MAX
#define AFSX_FNAME_MAX 256
#endif

#ifndef AFSX_PATH_MAX
#define AFSX_PATH_MAX 1024
#endif

extern int LINUX_AFSX_connect(void);
extern int LINUX_AFSX_ping(void);
/**
 * Creates a new file/dir in the dentry dp
 * @param dest is the encoded filename destination ptr
 * @param is_file is (AFSX_IS_DIR/AFSX_IS_FILE)
 * @param dp is the containing dentry
 * @return 0 on success
 */
extern int UCAFS_create(char ** dest, int is_file, struct dentry * dp);

extern int LINUX_AFSX_realname(char ** dest, char * fname, struct dentry * dp);
extern int LINUX_AFSX_lookup(char ** dest, struct dentry * dp);
extern int LINUX_AFSX_delfile(char ** dest, struct dentry * dp);
extern int UCAFS_store(struct vcache * avc, struct vrequest * areq);
extern int UCAFS_fetch(struct vcache * avc, struct vrequest * areq);
#endif
