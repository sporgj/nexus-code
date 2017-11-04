#include "nexus_module.h"
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include "nexus_util.h"


#define MAX_CMD_RESP_SIZE 1024

struct nexus_cmd_queue {
    wait_queue_head_t   daemon_waitq;
    struct mutex        lock;

    uint32_t            cmd_len;
    uint8_t           * cmd_data;

    uint8_t             active;
    uint8_t             complete;
    uint8_t             error;
    
    uint32_t            resp_len;
    uint8_t           * resp_data;
};



/* major & minor numbers for our modules */
static struct class * nexus_class     = NULL;
static int            nexus_major_num = 0;


static struct nexus_cmd_queue cmd_queue;

/***********************/
/* Stuff to get rid of */
/***********************/

static struct nexus_mod nexus_device;
struct nexus_mod * dev = &nexus_device;

mid_t message_counter = 0;


DEFINE_MUTEX(xfer_buffer_mutex);
DEFINE_MUTEX(message_counter_mutex);

/***********************/
/***********************/


static int
nexus_open(struct inode * inode,
	   struct file  * fp)
{
    unsigned long flags    = 0;
    int           acquired = 0;

    spin_lock_irqsave(&(dev->dev_lock), flags);
    {
        if (dev->daemon == NULL) {
            dev->daemon      = current;
            fp->private_data = dev;
            acquired         = 1;
        }
    }
    spin_unlock_irqrestore(&(dev->dev_lock), flags);

    if (acquired == 0) {
        return -EBUSY;
    }

    return 0;
}

static int
nexus_release(struct inode * inode,
	      struct file  * fp)
{
    /* grab the lock, reset all variables */
    unsigned long flags = 0;

    nexus_clear_volume_list();

    spin_lock_irqsave(&(dev->dev_lock), flags);
    {
        dev->daemon = NULL;
    }
    spin_unlock_irqrestore(&(dev->dev_lock), flags);

    return 0;
}

static ssize_t
nexus_read(struct file * filp,
	   char __user * buf,
	   size_t        count,
	   loff_t      * f_pos)
{
    size_t len;


    nexus_printk("Read of size %lu\n", count);


    if (cmd_queue.active == 0) {
	return 0;
    }

    if (count == 0) {
	return cmd_queue.cmd_len;
    }

    if (count < cmd_queue.cmd_len) {
	return -EINVAL;
    }
    
    copy_to_user(buf, cmd_queue.cmd_data, cmd_queue.cmd_len);

    return cmd_queue.cmd_len;
}

static ssize_t
nexus_write(struct file       * fp,
            const char __user * buf,
            size_t              count,
            loff_t *            f_pos)
{
    uint8_t * resp = NULL;
    int       ret  = 0;
    
    // check size of resp
    // too large: set error flag in cmd_queue, mark cmd_queue complete, and return -EINVAL
    if (count > MAX_CMD_RESP_SIZE) {
	return -EINVAL;
    }

    
    // kmalloc buffer for resp
    resp = kmalloc(count, GFP_KERNEL);

    if (PTR_ERR(resp)) {
	NEXUS_ERROR("Could not allocate kernel memory for response\n");
	return -ENOMEM;
    }
    
    // copy_from_user
    ret = copy_from_user(resp, buf, count);
    
    if (ret) {
	NEXUS_ERROR("Could not copy response from userspace\n");
	return -EFAULT;
    }
    
    // set resp fields in cmd_queue
    cmd_queue.resp_data = resp;
    cmd_queue.resp_len  = count;
    
    __asm__ ("":::"memory");

    // mark cmd_queue as complete
    cmd_queue.complete  = 1;
    
    // return count;
    return count;
}

static long
nexus_ioctl(struct file    * filp,
	    unsigned int     cmd,
	    unsigned long    arg)
{
    int      err     = 0;
    size_t   pathlen = 0;
    char   * path    = NULL;

    if (_IOC_TYPE(cmd) != NEXUS_IOC_MAGIC) {
        return -ENOTTY;
    }

    if (_IOC_NR(cmd) > NEXUS_IOC_MAXNR) {
        return -ENOTTY;
    }

    switch (cmd) {
    case IOCTL_ADD_PATH:
        /* copy the path len */
        if (copy_from_user(&pathlen, (size_t *)arg, sizeof(size_t))) {
            NEXUS_ERROR("copy_from_user FAILED\n");
            return -EFAULT;
        }

        /* allocate the path for the buffer */
        path = (char *)kzalloc(pathlen + 1, GFP_KERNEL);
        if (path == NULL) {
            NEXUS_ERROR("allocation error");
            return -ENOMEM;
        }

        /* copy the string from userspace */
        if (copy_from_user(path, (char *)arg, pathlen)) {
            NEXUS_ERROR("copy_from_user failed\n");
            return -EFAULT;
        }

        path[pathlen] = '\0';
        printk(KERN_INFO "path: %s\n", path);

        if (nexus_add_volume(path)) {
            NEXUS_ERROR("adding '%s' FAILED\n", path);
            err = -1;
        }

        kfree(path);
        break;

    case IOCTL_MMAP_SIZE:

        if (copy_to_user((char *)arg, &dev->xfer_len, sizeof(dev->xfer_len))) {
            NEXUS_ERROR("sending mmap order FAILED\n");
            err = -1;
        }
        break;

    default:
        err = -1;
    }

    return err;
}

static int
nexus_mmap_fault(struct vm_area_struct * vma,
		 struct vm_fault       * fault_info)
{

    // Should never fault, the mapping was screwed up.

    
    char        * addr  = NULL;
    struct page * page  = NULL;
    pgoff_t       index = fault_info->pgoff;

    if (index >= dev->xfer_pages) {
        NEXUS_ERROR("mmap_fault pgoff=%d, pages=%d\n", (int)index, dev->xfer_pages);
        return VM_FAULT_NOPAGE;
    }

    /* convert the address to a page */
    addr = dev->xfer_buffer + (index << PAGE_SHIFT);
    page = virt_to_page(addr);

    /*
    NEXUS_ERROR("nexus_fault: index=%d (%p), current=%d (%s) virt=%p page=%p\n",
          (int)index, addr, (int)current->pid, current->comm,
          fault_info->virtual_address, page);
          */

    if (!page) {
        return VM_FAULT_SIGBUS;
    }

    // get_page(page);
    fault_info->page = page;


    return 0;
}

static struct vm_operations_struct mmap_ops = {
    .fault = nexus_mmap_fault
};

static int
nexus_mmap(struct file           * filp,
	   struct vm_area_struct * vma)
{
    struct page   * page      = NULL;
    unsigned long   user_addr = vma->vm_start;

    int err = 0;
    int i   = 0;

    vma->vm_ops           = &mmap_ops;
    vma->vm_flags        |= (VM_READ | VM_WRITE | VM_DONTCOPY | VM_IO | VM_LOCKED);
    vma->vm_private_data  = filp->private_data;

    for (i = 0; i < dev->xfer_pages; i++) {

        page = virt_to_page(dev->xfer_buffer + (i << PAGE_SHIFT));
        err  = vm_insert_page(vma, user_addr, page);

        if (err) {
            NEXUS_ERROR("mmap error (%d)\n", err);
            return err;
        }

        user_addr += PAGE_SIZE;
    }

    return 0;
}

static unsigned int
nexus_poll(struct file              * filp,
	   struct poll_table_struct * poll_tb)
{
    unsigned int  mask = POLLIN | POLLRDNORM;

    poll_wait(filp, &(cmd_queue.daemon_waitq), poll_tb);

    if (cmd_queue.active == 1) {
	return mask;
    }
    
    return 0;
}

static struct file_operations nexus_mod_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = nexus_ioctl,
    .open           = nexus_open,
    .release        = nexus_release,
    .mmap           = nexus_mmap,
    .write          = nexus_write,
    .read           = nexus_read,
    .poll           = nexus_poll
};

static int
proc_show(struct seq_file * sf,
	  void            * v)
{
    struct nexus_volume_path * curr;

    if (dev->daemon == NULL) {
        seq_printf(sf, "daemon offline :(\n");
    } else {
        seq_printf(sf, "daemon pid: %d\n", (int)dev->daemon->pid);
    }

    seq_printf(sf, "outb=%zu, inb=%zu\n", dev->outb_len, dev->inb_len);

    seq_printf(sf, "paths:\n");
    list_for_each_entry(curr, &nexus_volumes_head, list)
    {
        seq_printf(sf, "%s\n", curr->afs_path);
    }

    return 0;
}

static int
proc_open(struct inode * inode,
	  struct file  * file)
{
    return single_open(file, proc_show, NULL);
}

static struct file_operations nexus_proc_fops = {
    .open    = proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release
};


int
nexus_send_cmd(uint32_t    cmd_len,
	       uint8_t   * cmd_data,
	       uint32_t  * resp_len,
	       uint8_t  ** resp_data)
{
    int ret = 0;
    
    // acquire cmd_queue mutex
    ret = mutex_lock_interruptible(&(cmd_queue.lock));

    if (ret != 0) {
	NEXUS_ERROR("Command Queue Mutex lock was interrupted...\n");
	goto out2;
    }
    
    // set data + len
    // mark as active
    cmd_queue.cmd_data  = cmd_data;
    cmd_queue.cmd_len   = cmd_len;    
    cmd_queue.resp_len  = 0;
    cmd_queue.resp_data = NULL;
    
    cmd_queue.active    = 1;

    __asm__ ("":::"memory");
    
    // wakeup waiting daemon
    wake_up_interruptible(&(cmd_queue.daemon_waitq));

    // wait on kernel waitq until cmd is complete
    // ...Eh fuck it, lets just burn the cpu
    while (cmd_queue.complete == 0) schedule();

    __asm__ ("":::"memory");


    if (cmd_queue.error == 1) {
	ret = -1;
	
	goto out1;
    }
    
    // copy resp len/data ptrs
    *resp_len  = cmd_queue.resp_len;
    *resp_data = cmd_queue.resp_data;

    // reset cmd_queue
    cmd_queue.active    = 0;
    cmd_queue.complete  = 0;

 out1:
    
    // release mutex
    mutex_unlock(&(cmd_queue.lock));

 out2:
    
    return ret;
}


/**
 * hold dev->send_mutex
 */
int
nexus_mod_send(afs_op_type_t           type,
               XDR                   * xdrs,
               struct nx_daemon_rsp ** pp_reply,
               int                   * p_err)
{
    struct nx_daemon_rsp * p_reply     = NULL;
    struct afs_op_msg    * msg_out     = NULL;
    struct afs_op_msg    * msg_in      = NULL;

    size_t payload_len = (xdrs->x_private - xdrs->x_base);
    size_t inbound_len;

    int err = -1;

    
    if (NEXUS_IS_OFFLINE) {
        READPTR_UNLOCK();
        return -1;
    }

    /* write the message to the outbuffer buffer */
    msg_out         = (struct afs_op_msg *)dev->outb;
    msg_out->type   = type;
    msg_out->msg_id = ucrpc__genid();
    msg_out->len    = payload_len;

    dev->outb_len = AFS_OP_MSG_SIZE(msg_out);

    /* now, lets wait for the response */
    while (1) {

        DEFINE_WAIT(wait);

        if (NEXUS_IS_OFFLINE) {
            printk(KERN_ERR "process is offline :(");
            goto out;
        }

        wake_up_interruptible(&dev->outq);
        /* sleep the kernel thread */

        prepare_to_wait(&dev->msgq, &wait, TASK_INTERRUPTIBLE);

        /* the buffer is "empty", nothing to read */
        if (dev->inb_len == 0) {
            schedule();
        }

        finish_wait(&dev->msgq, &wait);

        msg_in      = (struct afs_op_msg *)(dev->inb);
        inbound_len = AFS_OP_MSG_SIZE(msg_in);

        // XXX: the following lines are redundant as the lock ensures that
        // messages cannot
        // be interleaved. Remove this?
        /* JRL: Still an old reply? */
        if (msg_in->ack_id != msg_out->msg_id) {
            continue;
        }

        dev->inb_len -= inbound_len;

        /* allocate the response data */
        p_reply = kmalloc(inbound_len, GFP_KERNEL);
        if (p_reply == NULL) {
            *p_err    = msg_in->status;
            *pp_reply = NULL;

            NEXUS_ERROR("allocation error\n");

            goto out;
        }

        /* copy the XDR raw data and decode the fields */
        memcpy(p_reply->data, msg_in->payload, msg_in->len);
        xdrmem_create(&p_reply->xdrs, p_reply->data, msg_in->len, XDR_DECODE);

        *p_err    = msg_in->status;
        *pp_reply = p_reply;
        err       = 0;

        break;
    }

out:
    READPTR_UNLOCK();

    return err;
}

static int
init_cmd_queue(void)
{
    memset(&cmd_queue, 0, sizeof(struct nexus_cmd_queue));

    init_waitqueue_head(&(cmd_queue.daemon_waitq));

    mutex_init(&(cmd_queue.lock));
    
    return 0;
}


int
nexus_mod_init(void)
{
    dev_t devno = MKDEV(0, 0); // Dynamically assign the major number
    
    struct page * page = NULL;

    int ret   = 0;
    int order = NXMOD_XFER_ORDER;
    int i     = 0;


    nexus_printk("Initializing Nexus\n");

    init_cmd_queue();


    /********************************/
    /* Going to get rid of all this */
    /********************************/
    
    /* lets now initialize the data structures */
    memset(dev, 0, sizeof(struct nexus_mod));

    init_waitqueue_head(&dev->outq);
    init_waitqueue_head(&dev->msgq);

    mutex_init(&(dev->send_mutex));
    spin_lock_init(&(dev->dev_lock));

    // FIXME dev-outb != NULL?
    dev->outb = NXMOD_BUFFER_ALLOC();
    dev->inb  = NXMOD_BUFFER_ALLOC();

    if ((dev->outb == NULL) || (dev->inb == NULL)) {
        NEXUS_ERROR("allocating buffers failed\n");
        return -1;
    }

    /* allocate the transfer buffer */
    while (1) {
        if ((dev->xfer_buffer = (char *)__get_free_pages(GFP_KERNEL, order))) {
            break;
        }

        if (--order < 0) {
            printk(KERN_NOTICE "could not allocate xfer_buffer\n");
            return -1;
        }
    }

    dev->xfer_order = (order);
    dev->xfer_pages = (1 << order);
    dev->xfer_len   = (dev->xfer_pages << PAGE_SHIFT);

    dev->buffersize = NXMOD_BUFFER_SIZE;
    dev->inb_len    = 0;
    dev->outb_len   = 0;

    for (i = 0; i < dev->xfer_pages; i++) {
        page = virt_to_page(dev->xfer_buffer + (i << PAGE_SHIFT));
        get_page(page);
    }

    mutex_init(&xfer_buffer_mutex);


    /********************************/
    /********************************/
    /********************************/
    

    nexus_class = class_create(THIS_MODULE, "nexus");
    if (IS_ERR(nexus_class)) {
	NEXUS_ERROR("Failed to register Nexus device class\n");
	return PTR_ERR(nexus_class);
    }

    printk("intializing Nexus Control device\n");

    
    /* lets setup the character device */
    ret = alloc_chrdev_region(&devno, 0, 1, "nexus");

    if (ret < 0) {
	NEXUS_ERROR("Error registering device region for V3 devices\n");
	goto failure1;
    }

    nexus_major_num = MAJOR(devno);
    devno           = MKDEV(nexus_major_num, 1);

    NEXUS_DEBUG("Creating Nexus Device file: Major %d, Minor %d\n", nexus_major_num, MINOR(devno));
    

    cdev_init(&dev->cdev, &nexus_mod_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops   = &nexus_mod_fops;
    ret = cdev_add(&dev->cdev, devno, 1);

    if (ret != 0) {
	NEXUS_ERROR("Could not add nexus dev file\n");
        return ret;
    }


    device_create(nexus_class, NULL, devno, NULL, "nexus");

    
    
    /* create the proc file */
    proc_create_data("nexus", 0, NULL, &nexus_proc_fops, NULL);

    printk(KERN_INFO "nexus_mod: mounted, xfer: %zuB [%p - %p] %d pages\n",
           dev->xfer_len,
           dev->xfer_buffer,
           dev->xfer_buffer + dev->xfer_len,
           dev->xfer_pages);

    /* initialize the kernel data structures */
    nexus_kern_init();

    return 0;

 failure1:
    return -1;

}

int
nexus_mod_exit(void)
{
    dev_t devno;

    nexus_printk("Deinitializing Nexus\n");
    

    devno = MKDEV(nexus_major_num, 1);

    unregister_chrdev_region(devno, 1);

    cdev_del(&dev->cdev);

    device_destroy(nexus_class, devno);
    class_destroy(nexus_class);


    remove_proc_entry("nexus", NULL);
    
    
    return 0;
}
