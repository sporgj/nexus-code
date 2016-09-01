#ifndef _UCAFS_KERN_
#define _UCAFS_KERN_

#include <linux/types.h>
#include <linux/string.h>

#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"

#include "afs_secure.h"
#include "afsx.h"

extern struct rx_connection * conn;
extern int AFSX_IS_CONNECTED;

typedef struct {
    char srv_64bit;
    afs_uint32 moredata;
    int id;
    int buflen;
    void * buffer;
    afs_int32 len;
    afs_int32 off;
    struct vcache * avc;
    struct osi_file * fp;
    struct rx_connection * rx_conn;
    struct rx_call * afs_call;
    struct dcache * tdc;
    struct vrequest * areq;
} ucafs_ctx_t;

int __is_vnode_ignored(struct vcache * vcache, char ** dest);
int __is_dentry_ignored(struct dentry * dentry, char ** dest);


#endif
