#include "ucafs_module.h"

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
    mutex_lock_interruptible(&dev->mut);
    dev->daemon = NULL;
    atomic_inc(&ucafs_m_available);
    mutex_unlock(&dev->mut);

    return 0;
}

static int
ucafs_p_show(struct seq_file * sf, void * v)
{
    if (dev->daemon == NULL) {
        seq_printf(sf, "daemon pid: %d\n", (int)dev->daemon->pid);
    } else {
        seq_printf(sf, "daemon offline :(\n");
    }

    seq_printf(sf, "avail_read=%zu, avail_write=%zu\n", dev->avail_read,
               dev->avail_write);

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
        mutex_unlock(&dev->mut);
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
        mutex_unlock(&dev->mut);
        return -EFAULT;
    }

    /* this will be reincremented */
    dev->avail_write -= count;

    wake_up_interruptible(&dev->msgq);
    return count;
}

const struct file_operations ucafs_mod_fops = {.owner = THIS_MODULE,
                                               .open = ucafs_m_open,
                                               .release = ucafs_m_release,
                                               .write = ucafs_m_write,
                                               .read = ucafs_m_read};

const struct file_operations ucafs_proc_fops = {.open = ucafs_p_open,
                                                .read = seq_read,
                                                .llseek = seq_lseek,
                                                .release = single_release};

int
ucafs_mod_init(void)
{
    int ret;

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

    if (((dev->outb = UCMOD_BUFFER_ALLOC()) == NULL) ||
        ((dev->inb = UCMOD_BUFFER_ALLOC()) == NULL)) {
        ERROR("allocating buffers failed\n");
        return -1;
    }

    dev->buffersize = UCMOD_BUFFER_SIZE;
    dev->inb_len = dev->outb_len = 0;

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
    printk(KERN_INFO "ucafs_mod: mounted major=%d, minor=%d :)\n", uc_mod_major,
           uc_mod_minor);

    proc_create_data("ucafs_mod", 0, NULL, &ucafs_proc_fops, NULL);

    return 0;
}

int
ucafs_mod_exit(void)
{
    // TODO just free the buffers
    return 0;
}
