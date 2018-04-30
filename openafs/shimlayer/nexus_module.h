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


#include "nexus_afs.h"
#include "nexus_util.h"

#define FALSE 0
#define TRUE 1


extern struct task_struct * nexus_daemon;

#define NEXUS_IS_OFFLINE					\
    (nexus_daemon == NULL || task_is_stopped(nexus_daemon))



// ******** data transfer *********
#define MAX_FILESERVER_TRANSFER_BYTES  PAGE_SIZE // this is from AFS

extern const char * generic_databuf_command;

extern struct nexus_io_buffer {
    bool                    in_use;

    char                  * buffer;

    size_t                  size;

    wait_queue_head_t       waitq;

    struct page           * pages;
} nexus_iobuf;

// initialization routine called after device is mounted
int nexus_kern_init(void);

