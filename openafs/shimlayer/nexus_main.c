#include "nexus_module.h"
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include "nexus_util.h"
#include "nexus_volume.h"


struct nexus_mod * dev = NULL;

const char * generic_databuf_command = "{\n"
                                       "\"op\"   : %d,"
                                       "\n"
                                       "\"path\" : \"%s\","
                                       "\n"
                                       "\"offset\" : %zu,"
                                       "\n"
                                       "\"buflen\" : %zu,"
                                       "\n"
                                       "\"filesize\" : %zu"
                                       "\n"
                                       "}\n";


struct task_struct * nexus_daemon  = NULL;

/* data buffer stuff */
spinlock_t * nexus_databuffer_lock = NULL;
char       * nexus_databuffer_ptr  = NULL;

static struct page * databuf_pages = 0;


/* major & minor numbers for our modules */
static struct class * nexus_class     = NULL;
static int            nexus_major_num = 0;

static struct cdev    cdev;

static spinlock_t     dev_lock;


static int
nexus_open(struct inode * inode, struct file * fp)
{
    unsigned long flags    = 0;
    int           acquired = 0;

    spin_lock_irqsave(&dev_lock, flags);
    {
        if (nexus_daemon == NULL) {
            nexus_daemon     = current;
            fp->private_data = dev;
            acquired         = 1;
        }
    }
    spin_unlock_irqrestore(&dev_lock, flags);

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

    spin_lock_irqsave(&dev_lock, flags);
    {
        nexus_daemon = NULL;
    }
    spin_unlock_irqrestore(&dev_lock, flags);

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
            loff_t            * f_pos)
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


static int
nexus_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long uaddr = 0;

    int i = 0;

    int size = vma->vm_end - vma->vm_start;

    if (size > NEXUS_DATABUF_SIZE) {
        NEXUS_ERROR("mmap failed: available memory=%d, mmap size=%d\n",
                     NEXUS_DATABUF_SIZE, size);
    }

    // vma->vm_ops = &mmap_vmas;
    vma->vm_private_data = filp->private_data;


    uaddr = vma->vm_start;

    for (; i < NEXUS_DATABUF_PAGES; i++) {
        struct page * page = databuf_pages + i;

        int err = vm_insert_page(vma, uaddr, page);

        if (err) {
            NEXUS_ERROR("mmap error (%d)\n", err);
            return err;
        }

        uaddr += PAGE_SIZE;
    }

    printk(KERN_INFO "mmap successful (total_size=%d)\n", size);

    return 0;
}


static struct file_operations nexus_mod_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = nexus_ioctl,
    .mmap           = nexus_mmap,
    .open           = nexus_open,
    .release        = nexus_release,
    .write          = nexus_write,
    .read           = nexus_read
};

static int
proc_show(struct seq_file * sf, void * v)
{
    if (nexus_daemon == NULL) {
        seq_printf(sf, "daemon offline :(\n");
    } else {
        seq_printf(sf, "daemon pid: %d\n", (int)nexus_daemon->pid);
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


static int
__alloc_mod_memory(void)
{
    int i = 0;

    databuf_pages = alloc_pages(GFP_KERNEL, NEXUS_DATABUF_ORDER);

    if (databuf_pages == NULL) {
	printk(KERN_ERR "could not allocate pages (order=%d)\n", NEXUS_DATABUF_ORDER);
	return -ENOMEM;
    }

    // pin the pages
    for (; i < NEXUS_DATABUF_PAGES; i++) {
	struct page * page = databuf_pages + i;

        mark_page_reserved(page);
    }

    nexus_databuffer_ptr  = page_address(databuf_pages);
    nexus_databuffer_lock = nexus_kmalloc(sizeof(spinlock_t), GFP_KERNEL);

    spin_lock_init(nexus_databuffer_lock);

    return 0;
}

static void
__free_mod_memory(void)
{
    int i = 0;

    for (; i < NEXUS_DATABUF_PAGES; i++) {
	struct page * page = databuf_pages + i;

        free_reserved_page(page);
    }

    nexus_databuffer_ptr  = NULL;
    // XXX: check if the lock is unused?
    nexus_kfree(nexus_databuffer_lock);
}

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

    if (__alloc_mod_memory()) {
        NEXUS_ERROR("could not allocate module memory\n");
        return -ENOMEM;
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

    cdev_init(&cdev, &nexus_mod_fops);
    cdev.owner = THIS_MODULE;
    cdev.ops   = &nexus_mod_fops;
    ret = cdev_add(&cdev, devno, 1);

    if (ret != 0) {
	NEXUS_ERROR("Could not add nexus dev file\n");
        return ret;
    }


    device_create(nexus_class, NULL, devno, NULL, "nexus");


    /* create the proc file */
    proc_create_data("nexus", 0, NULL, &nexus_proc_fops, NULL);

    printk(KERN_INFO "nexus_mod: successfully mounted. pages=%d, size=%d\n",
           NEXUS_DATABUF_PAGES,
           NEXUS_DATABUF_SIZE);

    /* initialize the kernel data structures */
    nexus_kern_init();

    return 0;

 failure1:
    __free_mod_memory();

    return -1;

}

int
nexus_mod_exit(void)
{
    dev_t devno;

    nexus_printk("Deinitializing Nexus\n");


    devno = MKDEV(nexus_major_num, 1);

    unregister_chrdev_region(devno, 1);

    cdev_del(&cdev);

    device_destroy(nexus_class, devno);
    class_destroy(nexus_class);


    remove_proc_entry("nexus", NULL);

    __free_mod_memory();

    return 0;
}
