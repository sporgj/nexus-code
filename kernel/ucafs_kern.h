#ifndef _UCAFS_KERN_
#define _UCAFS_KERN_

#include <linux/types.h>
#include <linux/string.h>

#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"

#include "ucafs_prototypes.h"
#include "afsx.h"

extern struct rx_connection * conn;
extern int AFSX_IS_CONNECTED;

typedef struct {
    int id;
    uint8_t srv_64bit;
    int buflen;
    void * buffer;
    int32_t len;
    int32_t off;
    int32_t file_offset;
    struct rx_call * afs_call;
    struct rx_connection * rx_conn;
    struct vrequest * areq;
    struct rx_connection * udp_conn;
} ucafs_ctx_t;

int __is_vnode_ignored(struct vcache * vcache, char ** dest);
int __is_dentry_ignored(struct dentry * dentry, char ** dest);

struct rx_connection * __get_conn(void);
void __put_conn(struct rx_connection * c);

char *
uc_mkpath(const char * parent_path, const char * fname);

ucafs_entry_type
vnode_type(struct vcache * avc);

ucafs_entry_type
vnode_type(struct vcache * avc);

#endif
