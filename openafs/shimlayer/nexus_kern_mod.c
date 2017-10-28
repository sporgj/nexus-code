#include "nexus_module.h"
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "nexus_mod: " fmt, ##args)

static struct nexus_mod   nexus_device;
struct nexus_mod        * dev = &nexus_device;

/* major & minor numbers for our modules */
static int uc_mod_major            = 0;
static int uc_mod_minor            = 0;
static int uc_mod_devno            = 0;

static int nexus_module_is_mounted = 0;

mid_t msg_counter = 0;

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

    clear_watchlist();

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
              loff_t            * f_pos)
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
nexus_ioctl(struct file   * filp,
	      unsigned int    cmd,
	      unsigned long   arg)
{
    char * path = NULL;
    int    err  = 0;
    int    len  = 0;

    if (_IOC_TYPE(cmd) != NEXUS_IOC_MAGIC) {
        return -ENOTTY;
    }

    if (_IOC_NR(cmd)    > NEXUS_IOC_MAXNR) {
        return -ENOTTY;
    }

    switch (cmd) {
    case IOCTL_ADD_PATH:

	len  = strlen_user((char *)arg);
        path = (char *)kmalloc(len + 1, GFP_KERNEL);

	printk(KERN_WARNING "Unsafe string handling in Nexus IOCTL\n"); 
	dump_stack();
	

        if (path == NULL) {
            ERROR("allocation error");
            return -ENOMEM;
        }

        if (copy_from_user(path, (char *)arg, len)) {
            ERROR("copy_from_user failed\n");
            return -EFAULT;
        }

        path[len] = '\0';
        printk(KERN_INFO "path: %s\n", path);

        if (add_path_to_watchlist(path)) {
            ERROR("adding '%s' FAILED\n", path);
            err = -1;
        }

        kfree(path);
        break;

    case IOCTL_MMAP_SIZE:
	
        if (copy_to_user((char *)arg, &dev->xfer_len, sizeof(dev->xfer_len))) {
            ERROR("sending mmap order FAILED\n");
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
        ERROR("mmap_fault pgoff=%d, pages=%d\n", (int)index, dev->xfer_pages);
        return VM_FAULT_NOPAGE;
    }

    /* convert the address to a page */
    addr = dev->xfer_buffer + (index << PAGE_SHIFT);
    page = virt_to_page(addr);
    
    ERROR("nexus_fault: index=%d (%p), current=%d (%s) virt=%p page=%p\n",
          (int)index, addr, (int)current->pid, current->comm,
          fault_info->virtual_address, page);

    if (!page) {
        return VM_FAULT_SIGBUS;
    }

    //get_page(page);
    fault_info->page = page;

#if 0
    {
	struct page * page  = NULL;;
	int           ret   = 0;
	size_t        index = 0;

	index = (((unsigned long)fault_info->virtual_address - vma->vm_start) >> PAGE_SHIFT);

	if (index >= dev->xfer_pages) {
	    ERROR("mmap_error out of range index=%d", index);
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

    int err  = 0;
    int i    = 0;

    vma->vm_ops           = &mmap_ops;
    vma->vm_flags        |= (VM_READ | VM_WRITE | VM_DONTCOPY | VM_IO | VM_LOCKED);
    vma->vm_private_data  = filp->private_data;

    for (i = 0; i < dev->xfer_pages; i++) {

	page = virt_to_page(dev->xfer_buffer + (i << PAGE_SHIFT));
        err  = vm_insert_page(vma, user_addr, page);
	
        if (err) {
            ERROR("mmap error (%d)\n", err);
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
    watch_path_t * curr;

    if (dev->daemon == NULL) {
        seq_printf(sf, "daemon pid: %d\n", (int)dev->daemon->pid);
    } else {
        seq_printf(sf, "daemon offline :(\n");
    }

    seq_printf(sf, "outb=%zu, inb=%zu\n", dev->outb_len, dev->inb_len);

    seq_printf(sf, "paths:\n");

    list_for_each_entry(curr, watchlist_ptr, list)
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
 * hold dev->send_mut
 */
int
nexus_mod_send(uc_msg_type_t    type,
               XDR            * xdrs,
               reply_data_t  ** pp_reply,
               int            * p_err)
{
    reply_data_t * p_reply     = NULL;
    ucrpc_msg_t  * msg_out     = NULL;
    ucrpc_msg_t  * msg_in      = NULL; 
    size_t         payload_len = (xdrs->x_private - xdrs->x_base);

    int            err = -1;

    
    if (NEXUS_IS_OFFLINE) {
        READPTR_UNLOCK();
        return -1;
    }

    /* write the message to the buffer */
    msg_out           = (ucrpc_msg_t *)dev->outb;
    msg_out->type     = type;
    msg_out->msg_id   = ucrpc__genid();
    msg_out->len      = payload_len;

    dev->outb_len     = MSG_SIZE(msg_out);


    
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

        msg_in = (ucrpc_msg_t *)(dev->inb);


	/* JRL: Still an old reply? */
	if (msg_in->ack_id != msg_out->msg_id) {
	    continue;
	}

	dev->inb_len -= MSG_SIZE(msg_in);

	/* allocate the response data */
	p_reply       = kmalloc((sizeof(reply_data_t) + msg_in->len), GFP_KERNEL);
	
	if (p_reply == NULL) {
	    
	    *p_err    = msg_in->status;
	    *pp_reply = NULL;
	    
	    ERROR("allocation error\n");
	    
	    goto out;
	}
	
	/* instantiate everything */
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
    struct page * page = NULL;

    int ret   = 0;
    int order = UCMOD_XFER_ORDER;
    int i     = 0;

    if (nexus_module_is_mounted) {
        printk(KERN_NOTICE "nexus_mod is already mounted\n");
        return 0;
    }

    ret = alloc_chrdev_region(&uc_mod_devno, 0, 1, "nexus_mod");

    if (ret) {
        printk(KERN_NOTICE "register_chrdev_region failed %d\n", ret);
        return ret;
    }

    /* lets now initialize the data structures */
    memset(dev, 0, sizeof(struct nexus_mod));

    init_waitqueue_head(&dev->outq);
    init_waitqueue_head(&dev->msgq);

    mutex_init(&(dev->send_mutex));
    spin_lock_init(&(dev->dev_lock));
    
    // FIXME dev-outb != NULL?
    dev->outb = UCMOD_BUFFER_ALLOC();
    dev->inb  = UCMOD_BUFFER_ALLOC();

    if ( (dev->outb == NULL) ||
	 (dev->inb  == NULL) ) {
        ERROR("allocating buffers failed\n");
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
    dev->xfer_pages = (1               << order);
    dev->xfer_len   = (dev->xfer_pages << PAGE_SHIFT);

    dev->buffersize = UCMOD_BUFFER_SIZE;
    dev->inb_len    = 0;
    dev->outb_len   = 0;
    
    for (i = 0; i < dev->xfer_pages; i++) {
        page = virt_to_page(dev->xfer_buffer + (i << PAGE_SHIFT));
        get_page(page);
    }

    mutex_init(&xfer_buffer_mutex);

    /* lets setup the character device */
    uc_mod_major = MAJOR(uc_mod_devno);
    uc_mod_minor = MINOR(uc_mod_devno);
    
    cdev_init(&dev->cdev, &nexus_mod_fops);

    dev->cdev.owner = THIS_MODULE;

    if ((ret = cdev_add(&dev->cdev, uc_mod_devno, 1))) {
        printk(KERN_ERR "adding %d cdev failed: %d\n", uc_mod_devno, ret);
        return ret;
    }

    nexus_module_is_mounted = 1;

    printk(KERN_INFO
           "nexus_mod: mounted (%d,%d), xfer: %zuB [%p - %p] %d pages\n",
           uc_mod_major,
	   uc_mod_minor,
	   dev->xfer_len,
	   dev->xfer_buffer,
           dev->xfer_buffer + dev->xfer_len,
	   dev->xfer_pages);

    proc_create_data("nexus_mod", 0, NULL, &nexus_proc_fops, NULL);

    nexus_kern_init();

    return 0;
}

int
nexus_mod_exit(void)
{
    // TODO just free the buffers
    return 0;
}
