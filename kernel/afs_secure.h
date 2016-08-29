#ifndef AFS_SGX_H
#define AFS_SGX_H

#define AFSX_FBOX_EXT ".fbox"
#define AFSX_LBOX_EXT ".lbox"

#ifndef AFSX_FNAME_MAX
#define AFSX_FNAME_MAX 256
#endif

#ifndef AFSX_PATH_MAX
#define AFSX_PATH_MAX 1024
#endif

extern int LINUX_AFSX_connect(void);
extern int LINUX_AFSX_ping(void);
extern int LINUX_AFSX_newfile(char ** dest, struct dentry * dp);
extern int LINUX_AFSX_realname(char ** dest, char * fname, struct dentry * dp);
extern int LINUX_AFSX_lookup(char ** dest, struct dentry * dp);
extern int LINUX_AFSX_delfile(char ** dest, struct dentry * dp);
extern int LINUX_AFSX_store(struct vcache * avc, struct vrequest * areq);
extern int UCAFS_fetch(struct vcache * avc, struct vrequest * areq);
#endif
