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

#define UCAFS_DEFAULT_XFER_SIZE PAGE_SIZE
#define UCAFS_ALLOC_XFER_BUFFER (void *)__get_free_page(GFP_KERNEL)

extern struct rx_connection * conn;
extern int UCAFS_IS_CONNECTED;

typedef struct {
    int id;
    int off;
    uint8_t srv_64bit;
    int total_len;
    int real_len;
    void * buffer;
    int buflen;
    char * path;
    uc_fbox_t fbox;
    struct vcache * avc;
    struct rx_connection * uc_conn;
    /* fileserver stuff */
    struct afs_conn * tc;
    struct rx_connection * rx_conn;
    struct rx_call * afs_call;
} store_context_t;

typedef struct {
    int id;
    uint8_t srv_64bit;
    int buflen;
    void * buffer;
    int32_t len;
    int32_t off;
    int32_t file_offset;
    struct afs_conn * tc;
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
uc_vnode_type(struct vcache * avc);

afs_int32
_rxfs_fetchInit(struct afs_conn * tc,
                struct rx_connection * rxconn,
                struct vcache * avc,
                afs_offs_t base,
                afs_uint32 size,
                afs_int32 * alength,
                struct dcache * adc,
                struct osi_file * fP,
                struct rx_call ** afs_call);

#endif
