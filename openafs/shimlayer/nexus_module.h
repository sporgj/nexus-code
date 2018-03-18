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


struct nexus_mod {
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
