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
    dev->daemon = NULL;
    atomic_inc(&ucafs_m_available);

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

    seq_printf(sf, "outb=%zu, inb=%zu\n", dev->outb_len, dev->inb_len);

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

const struct file_operations ucafs_mod_fops = {.owner = THIS_MODULE,
                                               .open = ucafs_m_open,
                                               .release = ucafs_m_release,
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
