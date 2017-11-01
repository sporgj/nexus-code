#include "nexus_module.h"
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include "nexus_util.h"


static struct nexus_mod nexus_device;
struct nexus_mod * dev = &nexus_device;

/* major & minor numbers for our modules */
static struct class * nexus_class = NULL;
static int nexus_major_num = 0;

static int nexus_module_is_mounted = 0;

mid_t message_counter = 0;

DEFINE_MUTEX(xfer_buffer_mutex);
DEFINE_MUTEX(message_counter_mutex);

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
nexus_read(struct file * fp,
	   char __user * buf,
	   size_t        count,
	   loff_t      * f_pos)
{
    size_t len;

    /* we wait until we have data to send to the user */
    while (dev->outb_len == 0) {

        if (wait_event_interruptible(dev->outq, dev->outb_len > 0)) {
            return -ERESTARTSYS;
        }
    }

    /* send it to userspace */
    len = min(count, (dev->outb_len - dev->outb_sent));

    if (copy_to_user(buf, (dev->outb + dev->outb_sent), count)) {
        return -EFAULT;
    }

    dev->outb_sent += len;

    if (dev->outb_len == dev->outb_sent) {

        dev->outb_len  = 0;
        dev->outb_sent = 0;
    }

    return len;
}

static ssize_t
nexus_write(struct file       * fp,
            const char __user * buf,
            size_t              count,
            loff_t *            f_pos)
{
    /* copy the message in full */
    if (copy_from_user(dev->inb, buf, count)) {
        return -EFAULT;
    }

    /* this will be reincremented */
    dev->inb_len += count;

    wake_up_interruptible(&dev->msgq);

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

#if 0
    {
	struct page * page  = NULL;;
	int           ret   = 0;
	size_t        index = 0;

	index = (((unsigned long)fault_info->virtual_address - vma->vm_start) >> PAGE_SHIFT);

	if (index >= dev->xfer_pages) {
	    NEXUS_ERROR("mmap_error out of range index=%d", index);
	    return VM_FAULT_SIGBUS;
	}
	
	page = virt_to_page(dev->xfer_buffer + (index << PAGE_SHIFT));
	ret  = vm_insert_page(vma, (unsigned long)vmf->virtual_address, page);
    }
#endif

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

static struct file_operations nexus_mod_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = nexus_ioctl,
    .open           = nexus_open,
    .release        = nexus_release,
    .mmap           = nexus_mmap,
    .write          = nexus_write,
    .read           = nexus_read
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

int
nexus_mod_init(void)
{
    dev_t devno = MKDEV(0, 0); // Dynamically assign the major number
    
    struct page * page = NULL;

    int ret   = 0;
    int order = NXMOD_XFER_ORDER;
    int i     = 0;

    if (nexus_module_is_mounted) {
        printk(KERN_NOTICE "nexus_mod is already mounted\n");
        return 0;
    }

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

    nexus_module_is_mounted = 1;

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

    devno = MKDEV(nexus_major_num, 0);

    unregister_chrdev_region(devno, 1);

    cdev_del(&dev->cdev);

    device_destroy(nexus_class, devno);
    class_destroy(nexus_class);


    remove_proc_entry("nexus", NULL);
    
    
    // TODO just free the buffers
    return 0;
}
