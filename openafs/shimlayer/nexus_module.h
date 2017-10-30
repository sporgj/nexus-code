#pragma once

#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "rx/xdr.h"
#include "rx/xdr_prototypes.h"

// clang-format off
#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"
// clang-format on

#define MAX_FSERV_SIZE        PAGE_SIZE

#define NXKERN_NBR_DEVS       1
#define NXKERN_PIPE_BUFFER    PAGE_SIZE

#define NXMOD_PAGE_ORDER      0
#define NXMOD_BUFFER_SIZE     (PAGE_SIZE << NXMOD_PAGE_ORDER)
#define NXMOD_BUFFER_ALLOC()  (char *)get_zeroed_page(GFP_KERNEL)
#define NXMOD_BUFFER_FREE(x)  free_page(x)

#define NXMOD_XFER_ORDER      5
#define NEXUS_XFER_SIZE       (PAGE_SIZE << NXMOD_XFER_ORDER)

/* for the transfer buffers */
#define NEXUS_DATA_BUFPAGES (1)
#define NEXUS_DATA_BUFLEN (PAGE_SIZE << NEXUS_DATA_BUFPAGES)

#define FALSE 0
#define TRUE 1

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "nexus: " fmt " [%s():%d]", \
				   ##args, __func__, __LINE__)

/* the list of paths to watch for */
typedef struct {
    struct list_head list;
    int              path_len;
    char             afs_path[0];
} watch_path_t;

extern struct list_head * watchlist_ptr;

int add_path_to_watchlist(const char * path);
void clear_watchlist(void);

/* We should probably get rid of this, since there is only one. */

struct nexus_mod {
    wait_queue_head_t    msgq;

    wait_queue_head_t    outq;
    char *               outb;
    size_t               outb_len;
    size_t               outb_sent;

    char *               inb;
    size_t               inb_len;

        
    char *               xfer_buffer;
    int                  xfer_order;
    int                  xfer_pages;
    size_t               buffersize;
    size_t               xfer_len;

    struct mutex         send_mutex;
    
    spinlock_t           dev_lock;
    struct task_struct * daemon;
    
    struct cdev          cdev;
    
};

extern struct nexus_mod * dev;

#define NEXUS_IS_OFFLINE					\
    (dev->daemon == NULL || task_is_stopped(dev->daemon))

// initialization routine called after device is mounted
int nexus_kern_init(void);

extern struct mutex xfer_buffer_mutex;

extern mid_t message_counter;
extern struct mutex message_counter_mutex;

static inline mid_t
ucrpc__genid(void)
{
    mid_t counter;
    mutex_lock_interruptible(&message_counter_mutex);
    {
	counter = (++message_counter);
    }
    mutex_unlock(&message_counter_mutex);

    return counter;
}

/* Is that what this thing is?? */
struct rpc_context {
    int              id;
    int              xfer_size;
    int              offset;
    int              buflen;
    int              total_size;
    char           * uaddr;
    char           * buffer;
    char           * path;
    struct rx_call * afs_call;
};


/* TODO: Remove these */
typedef struct rpc_context store_context_t;
typedef struct rpc_context fetch_context_t;

/* reply data from the wire */
struct reply_data {
    XDR  xdrs;
    char data[0];
};

/* TODO: Remove this */
typedef struct reply_data reply_data_t;

/* the name function to send data */
int
nexus_mod_send(afs_op_type_t   type,
               XDR           * xdrs,
               reply_data_t ** pp_rsp,
               int           * p_code);



/**
 * Acquires the lock to transfer messages to userspace
 * Drops the AFS global lock to allow for userspace daemon to access
 * metadata files.
 */
static inline caddr_t
READPTR_LOCK(void)
{
    /*printk(KERN_ERR "[send_mutex] %s (%d) waits\n", current->comm,
            (int)current->pid);*/
    AFS_GUNLOCK();
    if (mutex_lock_interruptible(&dev->send_mutex)) {
        AFS_GLOCK();
        ERROR("locking mutex failed\n");
        return 0;
    }

    /*printk(KERN_ERR "[send_mutex] %s (%d) locks\n", current->comm,
            (int)current->pid);*/
    /* clear the message at that pointer */
    memset(dev->outb, 0, sizeof(struct afs_op_msg));
    return (caddr_t)(((char *)dev->outb) + sizeof(struct afs_op_msg));
}

static inline void
READPTR_UNLOCK(void)
{
    /*printk(KERN_ERR "[send_mutex] %s (%d) left\n", current->comm,
            (int)current->pid);*/
    mutex_unlock(&dev->send_mutex);
    RX_AFS_GLOCK();
}

/* for trylock, we only drop the glock if it's successfully acquired */
static inline caddr_t
READPTR_TRYLOCK(void)
{
    if (mutex_is_locked(&dev->send_mutex)) {
        return 0;
    }

    return READPTR_LOCK();
}

static inline void
READPTR_TRY_UNLOCK(void)
{
    if (mutex_is_locked(&dev->send_mutex)) {
        mutex_unlock(&dev->send_mutex);
    }
}

// hold READPTR_LOCK()
static inline size_t
READPTR_BUFLEN(void)
{
    return (dev->buffersize - sizeof(struct afs_op_msg));
}
