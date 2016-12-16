#pragma once

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/mutex.h>

#include "afs/ucafs_header.h"

#define UCKERN_NBR_DEVS 1
#define UCKERN_PIPE_BUFFER PAGE_SIZE

#define UCMOD_PAGE_ORDER 0
#define UCMOD_BUFFER_SIZE (PAGE_SIZE << UCMOD_PAGE_ORDER)
#define UCMOD_BUFFER_ALLOC()                                                   \
    (char *)alloc_pages(GFP_KERNEL | __GFP_ZERO, UCMOD_PAGE_ORDER)
#define UCMOD_BUFFER_FREE(x) free_pages(x, UCMOD_PAGE_ORDER)

/* private stuff */
struct ucafs_mod {
    wait_queue_head_t kq, uq;
    uint8_t *buffer, *end;
    size_t buffersize;
    char *outb, *inb;
    size_t avail_read, avail_write;
    pid_t daemon_pid;
    struct mutex mut;
    struct cdev cdev;
};

extern struct ucafs_mod * dev;
