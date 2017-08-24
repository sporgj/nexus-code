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

#include "afs/ucafs_header.h"
#include "rx/xdr.h"
#include "rx/xdr_prototypes.h"

// clang-format off
#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"
// clang-format on

#define MAX_FSERV_SIZE PAGE_SIZE

#define UCKERN_NBR_DEVS 1
#define UCKERN_PIPE_BUFFER PAGE_SIZE

#define UCMOD_PAGE_ORDER 0
#define UCMOD_BUFFER_SIZE (PAGE_SIZE << UCMOD_PAGE_ORDER)
#define UCMOD_BUFFER_ALLOC() (char *)get_zeroed_page(GFP_KERNEL)
#define UCMOD_BUFFER_FREE(x) free_page(x)

#define UCMOD_XFER_ORDER 5
#define UCAFS_XFER_SIZE (PAGE_SIZE << UCMOD_XFER_ORDER)

typedef struct {
    struct list_head list;
    int path_len;
    char afs_path[0];
} watch_path_t;

extern struct list_head * watchlist_ptr;

int add_path_to_watchlist(const char * path);
void clear_watchlist(void);

struct ucafs_mod {
    wait_queue_head_t outq, msgq;
    char * outb, * inb, *xfer_buffer;
    int xfer_order, xfer_pages;
    size_t buffersize, outb_len, inb_len, outb_sent, xfer_len;
    struct task_struct * daemon;
    struct cdev cdev;
    struct mutex send_mut;
};

extern struct ucafs_mod * dev;

int ucafs_kern_init(void);

#define UCAFS_IS_OFFLINE                                                       \
    (dev->daemon == NULL || task_is_stopped(dev->daemon))

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs: " fmt " [%s():%d]", \
    ##args, __func__, __LINE__)

static DEFINE_MUTEX(xfer_buffer_mutex);

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
    int id, xfer_size, offset, buflen, total_size;
    char *uaddr, *buffer, *path;
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

static inline caddr_t
READPTR_LOCK(void)
{
    /*printk(KERN_ERR "[send_mut] %s (%d) waits\n", current->comm,
            (int)current->pid);*/
    AFS_GUNLOCK();
    if (mutex_lock_interruptible(&dev->send_mut)) {
        AFS_GLOCK();
        ERROR("locking mutex failed\n");
        return 0;
    }

    /*printk(KERN_ERR "[send_mut] %s (%d) locks\n", current->comm,
            (int)current->pid);*/
    /* clear the message at that pointer */
    memset(dev->outb, 0, sizeof(ucrpc_msg_t));
    return (caddr_t)(((char *)dev->outb) + sizeof(ucrpc_msg_t));
}

static inline caddr_t
READPTR_TRYLOCK(void)
{
    /* trylock returns 0 on failure */
    if (!mutex_trylock(&dev->send_mut)) {
        return 0;
    }

    /* for trylock, we only drop the glock if it's successfully acquired */
    AFS_GUNLOCK();

    memset(dev->outb, 0, sizeof(ucrpc_msg_t));
    return (caddr_t)(((char *)dev->outb) + sizeof(ucrpc_msg_t));
}

static inline void
READPTR_TRY_UNLOCK(void)
{
    if (mutex_is_locked(&dev->send_mut)) {
        mutex_unlock(&dev->send_mut);
    }
}

static inline void
READPTR_UNLOCK(void)
{
    /*printk(KERN_ERR "[send_mut] %s (%d) left\n", current->comm,
            (int)current->pid);*/
    mutex_unlock(&dev->send_mut);
    RX_AFS_GLOCK();
}

// hold READPTR_LOCK()
static inline size_t
READPTR_BUFLEN(void)
{
    return (dev->buffersize - sizeof(ucrpc_msg_t));
}
