#include "nexus_module.h"
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include "nexus_util.h"
#include "nexus_volume.h"


struct nexus_mod * dev = NULL;


/* major & minor numbers for our modules */
static struct class * nexus_class     = NULL;
static int            nexus_major_num = 0;


static int
nexus_open(struct inode * inode, struct file * fp)
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
nexus_release(struct inode * inode, struct file * fp)
{
    /* grab the lock, reset all variables */
    unsigned long flags = 0;

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
    return 0;
}

static ssize_t
nexus_write(struct file       * fp,
            const char __user * buf,
            size_t              count,
            loff_t *            f_pos)
{
    return 0;
}

static long
nexus_ioctl(struct file * filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    if (_IOC_TYPE(cmd) != NEXUS_IOC_MAGIC) {
        return -ENOTTY;
    }

    if (_IOC_NR(cmd) > NEXUS_IOC_MAXNR) {
        return -ENOTTY;
    }

    switch (cmd) {
    case IOCTL_ADD_PATH: {
        char * path = kmalloc(PATH_MAX, GFP_KERNEL);

        if (path == NULL) {
            NEXUS_ERROR("Could not allocate space for path\n");
            ret = -1;
            break;
        }

        ret = strncpy_from_user(path, (char *)arg, PATH_MAX);

        if ((ret == 0) || (ret == PATH_MAX)) {
            NEXUS_ERROR("Tried to register a path with invalid length (ret = %d)\n", ret);
            ret = -ERANGE;
            break;
        } else if (ret < 0) {
            NEXUS_ERROR("Error copying path from userspace\n");
            break;
        }

        /* copy the string from userspace */
        nexus_printk("path: %s\n", path);

        /* We need some way to check the input path against the actual file system structure....
         * Probably do a dentry lookup and verify that it esists....
         */
        if (path[0] == '\0') {
            NEXUS_ERROR("Tried to register empty path\n");
            return -1;
        }

        ret = create_nexus_volume(path);

        if (ret == -1) {
            NEXUS_ERROR("Could not create volume '%s'\n", path);
            ret = -1;
        }

        kfree(path);

        break;
    }

    default:
        ret = -1;
    }

    return ret;
}

static struct file_operations nexus_mod_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = nexus_ioctl,
    .open           = nexus_open,
    .release        = nexus_release,
    .write          = nexus_write,
    .read           = nexus_read
};

static int
proc_show(struct seq_file * sf, void * v)
{
    if (dev->daemon == NULL) {
        seq_printf(sf, "daemon offline :(\n");
    } else {
        seq_printf(sf, "daemon pid: %d\n", (int)dev->daemon->pid);
    }

    return 0;
}

static int
proc_open(struct inode * inode, struct file * file)
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
nexus_mod_init(void)
{
    dev_t devno = MKDEV(0, 0); // Dynamically assign the major number

    int ret   = 0;


    nexus_printk("Initializing Nexus\n");

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

    printk(KERN_INFO "nexus_mod: mounted pages\n");

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
