#include "ucafs_module.h"
#include <asm/pgtable.h>
#include <linux/mm.h>

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_mod: " fmt, ##args)

static struct ucafs_mod ucafs_m_device;
struct ucafs_mod * dev = &ucafs_m_device;

static atomic_t ucafs_m_available = ATOMIC_INIT(1);

/* major & minor numbers for our modules */
static int uc_mod_major = 0;
static int uc_mod_minor = 0;

static int uc_mod_devno = 0;

static int ucafs_module_is_mounted = 0;

mid_t msg_counter = 0;

static int
ucafs_m_open(struct inode * inode, struct file * fp)
{
    if (!atomic_dec_and_test(&ucafs_m_available)) {
        atomic_inc(&ucafs_m_available);
        return -EBUSY;
    }

    dev->daemon = current;
    fp->private_data = dev;

    return 0;
}

static int
ucafs_m_release(struct inode * inode, struct file * fp)
{
    /* grab the lock, reset all variables */
    dev->daemon = NULL;
    atomic_inc(&ucafs_m_available);
    clear_watchlist();

    return 0;
}

static int
ucafs_p_show(struct seq_file * sf, void * v)
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
ucafs_p_open(struct inode * inode, struct file * file)
{
    return single_open(file, ucafs_p_show, NULL);
}

static ssize_t
ucafs_m_read(struct file * fp, char __user * buf, size_t count, loff_t * f_pos)
{
    size_t len;

    /* we wait until we have data to send to the user */
    while (dev->outb_len == 0) {
        if (wait_event_interruptible(dev->outq, dev->outb_len > 0)) {
            return -ERESTARTSYS;
        }
    }

    /* send it to userspace */
    len = min(count, dev->outb_len - dev->outb_sent);
    if (copy_to_user(buf, dev->outb + dev->outb_sent, count)) {
        return -EFAULT;
    }

    dev->outb_sent += len;

    if (dev->outb_len == dev->outb_sent) {
        dev->outb_len = dev->outb_sent = 0;
    }

    return len;
}

static ssize_t
ucafs_m_write(struct file * fp,
              const char __user * buf,
              size_t count,
              loff_t * f_pos)
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
ucafs_m_ioctl(struct file * filp, unsigned int cmd, unsigned long arg)
{
    int err = 0, len;
    char * path;

    if (_IOC_TYPE(cmd) != UCAFS_IOC_MAGIC) {
        return -ENOTTY;
    }

    if (_IOC_NR(cmd) > UCAFS_IOC_MAXNR) {
        return -ENOTTY;
    }

    switch (cmd) {
    case IOCTL_ADD_PATH:
        len = strlen_user((char *)arg);
        path = (char *)kmalloc(len + 1, GFP_KERNEL);
        if (path == NULL) {
            err = -1;
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
ucafs_mmap_fault(struct vm_area_struct * vma, struct vm_fault * vmf)
{
    char * addr;
    struct page * page;
    pgoff_t index = vmf->pgoff;
    if (index >= dev->xfer_pages) {
        ERROR("mmap_fault pgoff=%d, pages=%d\n", (int)index, dev->xfer_pages);
        return VM_FAULT_NOPAGE;
    }

    /* convert the address to a page */
    addr = dev->xfer_buffer + (index << PAGE_SHIFT);
    page = virt_to_page(addr);
    ERROR("ucafs_fault: index=%d (%p), current=%d (%s) virt=%p page=%p\n",
          (int)index, addr, (int)current->pid, current->comm,
          vmf->virtual_address, page);

    if (!page) {
        return VM_FAULT_SIGBUS;
    }

    //get_page(page);
    vmf->page = page;

#if 0
    struct page * page;
    int ret = 0;
    size_t index =
        ((unsigned long)vmf->virtual_address - vma->vm_start) >> PAGE_SHIFT;
    if (index >= dev->xfer_pages) {
        ERROR("mmap_error out of range index=%d", index);
        return VM_FAULT_SIGBUS;
    }

    page = virt_to_page(dev->xfer_buffer + (index << PAGE_SHIFT));
    ret = vm_insert_page(vma, (unsigned long)vmf->virtual_address, page);
#endif

    return 0;
}

static struct vm_operations_struct mmap_ops = {.fault = ucafs_mmap_fault};

static int
ucafs_m_mmap(struct file * filp, struct vm_area_struct * vma)
{
    int i, err;
    struct page * page;
    unsigned long uaddr = vma->vm_start;

    vma->vm_ops = &mmap_ops;
    vma->vm_flags |= (VM_READ | VM_WRITE | VM_DONTCOPY | VM_IO | VM_LOCKED);
    vma->vm_private_data = filp->private_data;

    for (i = 0; i < dev->xfer_pages; i++) {
        page = virt_to_page(dev->xfer_buffer + (i << PAGE_SHIFT));
        err = vm_insert_page(vma, uaddr, page);
        if (err) {
            ERROR("mmap error (%d)\n", err);
            return err;
        }

        uaddr += PAGE_SIZE;
    }

    return 0;
}

const struct file_operations ucafs_mod_fops = {.owner = THIS_MODULE,
                                               .unlocked_ioctl = ucafs_m_ioctl,
                                               .open = ucafs_m_open,
                                               .release = ucafs_m_release,
                                               .mmap = ucafs_m_mmap,
                                               .write = ucafs_m_write,
                                               .read = ucafs_m_read};

const struct file_operations ucafs_proc_fops = {.open = ucafs_p_open,
                                                .read = seq_read,
                                                .llseek = seq_lseek,
                                                .release = single_release};

/**
 * hold dev->send_mut
 */
int
ucafs_mod_send(uc_msg_type_t type,
               XDR * xdrs,
               reply_data_t ** pp_reply,
               int * p_err)
{
    int err = -1;
    mid_t id;
    reply_data_t * p_reply;
    ucrpc_msg_t * msg;
    size_t payload_len = (xdrs->x_private - xdrs->x_base);

    if (UCAFS_IS_OFFLINE) {
        READPTR_UNLOCK();
        return -1;
    }

    /* write the message to the buffer */
    msg = (ucrpc_msg_t *)dev->outb;
    msg->type = type;
    msg->msg_id = id = ucrpc__genid();
    msg->len = payload_len;
    dev->outb_len = MSG_SIZE(msg);

    /* now, lets wait for the response */
    while (1) {
        DEFINE_WAIT(wait);
        if (UCAFS_IS_OFFLINE) {
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

        msg = (ucrpc_msg_t *)dev->inb;
        if (msg->ack_id == id) {
            dev->inb_len -= MSG_SIZE(msg);

            /* allocate the response data */
            p_reply = kmalloc(sizeof(reply_data_t) + msg->len, GFP_KERNEL);
            if (p_reply == NULL) {
                *p_err = msg->status;
                *pp_reply = NULL;
                ERROR("allocation error\n");
                goto out;
            }

            /* instantiate everything */
            memcpy(p_reply->data, msg->payload, msg->len);
            xdrmem_create(&p_reply->xdrs, p_reply->data, msg->len, XDR_DECODE);

            *p_err = msg->status;
            *pp_reply = p_reply;

            err = 0;
            break;
        }
    }

out:
    READPTR_UNLOCK();

    return err;
}

int
ucafs_mod_init(void)
{
    int ret, order = UCMOD_XFER_ORDER, i;
    struct page * page;

    if (ucafs_module_is_mounted) {
        printk(KERN_NOTICE "ucafs_mod is already mounted\n");
        return 0;
    }

    ret = alloc_chrdev_region(&uc_mod_devno, 0, 1, "ucafs_mod");
    if (ret) {
        printk(KERN_NOTICE "register_chrdev_region failed %d\n", ret);
        return ret;
    }

    /* lets now initialize the data structures */
    memset(dev, 0, sizeof(struct ucafs_mod));

    init_waitqueue_head(&dev->outq);
    init_waitqueue_head(&dev->msgq);

    mutex_init(&dev->send_mut);

    // FIXME dev-outb != NULL?
    if (((dev->outb = UCMOD_BUFFER_ALLOC()) == NULL) ||
        ((dev->inb = UCMOD_BUFFER_ALLOC()) == NULL)) {
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

    dev->xfer_order = order;
    dev->xfer_pages = (1 << (order));
    dev->xfer_len = (dev->xfer_pages << PAGE_SHIFT);

    dev->buffersize = UCMOD_BUFFER_SIZE;
    dev->inb_len = dev->outb_len = 0;

    for (i = 0; i < dev->xfer_pages; i++) {
        page = virt_to_page(dev->xfer_buffer + (i << PAGE_SHIFT));
        get_page(page);
    }

    mutex_init(&xfer_buffer_mutex);

    /* lets setup the character device */
    uc_mod_major = MAJOR(uc_mod_devno);
    uc_mod_minor = MINOR(uc_mod_devno);
    cdev_init(&dev->cdev, &ucafs_mod_fops);
    dev->cdev.owner = THIS_MODULE;
    if ((ret = cdev_add(&dev->cdev, uc_mod_devno, 1))) {
        printk(KERN_ERR "adding %d cdev failed: %d\n", uc_mod_devno, ret);
        return ret;
    }

    ucafs_module_is_mounted = 1;
    printk(KERN_INFO
           "ucafs_mod: mounted (%d,%d), xfer: %zuB [%p - %p] %d pages\n",
           uc_mod_major, uc_mod_minor, dev->xfer_len, dev->xfer_buffer,
           dev->xfer_buffer + dev->xfer_len, dev->xfer_pages);

    proc_create_data("ucafs_mod", 0, NULL, &ucafs_proc_fops, NULL);

    ucafs_kern_init();

    return 0;
}

int
ucafs_mod_exit(void)
{
    // TODO just free the buffers
    return 0;
}
