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


#include "afs.h"
#include "nexus.h"
#include "nexus_util.h"

#define FALSE 0
#define TRUE 1





typedef uint16_t mid_t;

extern struct list_head nexus_volumes_head;

/* the list of paths to watch for */
struct nexus_volume_path {
    struct list_head list;
    int              path_len;
    char             afs_path[0];
};

/** Add a new NeXUS volume to the watchlist */
int nexus_add_volume(const char * path);

void nexus_clear_volume_list(void);

/* We should probably get rid of this, since there is only one. */

struct nexus_mod {
    wait_queue_head_t    msgq;

    wait_queue_head_t    outq;
    char *               outb;
    size_t               outb_len;
    size_t               outb_sent;

    char *               inb;
    size_t               inb_len;

    struct mutex         send_mutex;

    spinlock_t           dev_lock;
    struct task_struct * daemon;

    struct cdev cdev;
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
struct kern_xfer_context {
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
typedef struct kern_xfer_context fetch_context_t;

/* reply data from the wire */
struct nx_daemon_rsp {
    XDR  xdrs;
    char data[0];
};

/* the name function to send data */
int
nexus_mod_send(afs_op_type_t   type,
               XDR           * xdrs,
               struct nx_daemon_rsp ** pp_rsp,
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
        NEXUS_ERROR("locking mutex failed\n");
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
