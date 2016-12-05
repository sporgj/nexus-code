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

#define DEFAULT_XFER_SIZE PAGE_SIZE
#define ALLOC_XFER_BUFFER (void *)__get_free_page(GFP_KERNEL)
#define FREE_XFER_BUFFER(ptr) __free_page(ptr)

extern struct rx_connection * conn;
extern int UCAFS_IS_CONNECTED;

typedef struct {
    int id;
    int off;
    int srv_64bit;
    int total_len;
    int real_len;
    int fbox_len;
    int buflen;
    void * buffer;
    char * path;
    struct vcache * avc;
    struct rx_connection * uc_conn;
    /* fileserver stuff */
    struct afs_conn * tc;
    struct rx_connection * rx_conn;
    struct rx_call * afs_call;
} store_context_t, fetch_context_t;

typedef struct {
    int id;
    int srv_64bit;
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

int
_ucafs_init_fetch(struct afs_conn * tc,
                  struct rx_connection * rxconn,
                  struct vcache * avc,
                  afs_offs_t base,
                  afs_uint32 size,
                  afs_int32 * alength,
                  int * srv_64bit,
                  struct rx_call ** afs_call);

int
_ucafs_end_fetch(struct rx_call * afs_call,
                 struct afs_FetchOutput * o,
                 int srv_64bit,
                 int error);

int
_ucafs_read_fbox(struct rx_call * acall, int length, uc_fbox_t **);

#endif
