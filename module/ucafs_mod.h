#pragma once

#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "afs/ucafs_header.h"
#include "rx/xdr.h"
#include "rx/xdr_prototypes.h"

// clang-format off
#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"
// clang-format on

#define UCKERN_NBR_DEVS 1
#define UCKERN_PIPE_BUFFER PAGE_SIZE

#define UCMOD_PAGE_ORDER 2
#define UCMOD_BUFFER_SIZE (PAGE_SIZE << UCMOD_PAGE_ORDER)
#define UCMOD_BUFFER_ALLOC()                                                   \
    (char *)alloc_pages(GFP_KERNEL | __GFP_ZERO, UCMOD_PAGE_ORDER)
#define UCMOD_BUFFER_FREE(x) free_pages(x, UCMOD_PAGE_ORDER)

#define UCXFER_ALLOC() (uint8_t *)alloc_pages(GFP_KERNEL, UCMOD_PAGE_ORDER - 1)
#define UCXFER_FREE(x) free_pages((unsigned long)x, UCMOD_PAGE_ORDER - 1)

/* data structures for our module */
struct ucafs_mod {
    wait_queue_head_t kq, rq, wq;
    uint8_t *buffer, *end;
    size_t buffersize;
    char *outb, *inb;
    size_t avail_read, avail_write, msg_len;
    struct task_struct * daemon;
    struct mutex mut;
    struct cdev cdev;
};

extern struct ucafs_mod * dev;

#define UCAFS_IS_OFFLINE                                                       \
    (dev->daemon == NULL || task_is_stopped_or_traced(dev->daemon))

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs: " fmt, ##args)

static DEFINE_MUTEX(mut_msg_counter);
static inline mid_t
ucrpc__genid(void)
{
    mid_t counter;
    mutex_lock_interruptible(&mut_msg_counter);
    counter = (++msg_counter);
    mutex_unlock(&mut_msg_counter);

    return counter;
}

typedef struct {
    int id;
    int srv_64bit;
    size_t total_size;
    char * buffer;
    uint32_t buflen;
    uint8_t * path;
    struct vcache * avc;
    struct rx_connection * rx_conn;
    struct afs_conn * tc;
    struct rx_call * afs_call;
} store_context_t, fetch_context_t;

/* reply data from the wire */
typedef struct {
    XDR xdrs;
    char data[0];
} reply_data_t;

/* the name function to send data */
int
ucafs_mod_send(uc_msg_type_t type,
               XDR * xdrs,
               reply_data_t ** pp_rsp,
               int * p_code);

int
ucafs_mod_send1(uc_msg_type_t type,
                uc_msg_subtype_t subtype,
                uint8_t * buffer, // make sure it is large enough
                XDR * xdrs,
                reply_data_t ** pp_rsp,
                int * p_code);

static inline caddr_t
READPTR_LOCK(void)
{
    if (mutex_lock_interruptible(&dev->mut)) {
        ERROR("locking mutex failed\n");
        return 0;
    }

    /* clear the message at that pointer */
    memset(dev->outb, 0, sizeof(ucrpc_msg_t));
    return (caddr_t)((char *)dev->outb + sizeof(ucrpc_msg_t));
}

static inline void
READPTR_TRY_UNLOCK(void)
{
    if (mutex_is_locked(&dev->mut)) {
        mutex_unlock(&dev->mut);
    }
}

static inline void
READPTR_UNLOCK(void)
{
    mutex_unlock(&dev->mut);
}

// hold READPTR_LOCK()
static inline size_t
READPTR_BUFLEN(void)
{
    size_t len = (dev->buffersize - dev->avail_read - sizeof(ucrpc_msg_t));
    len -= (len % 16);
    return len;
}
