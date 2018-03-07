
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>

#include "nexus_volume.h"
#include "nexus_util.h"


static DEFINE_SPINLOCK(volume_list_lock);
static struct list_head volume_list = LIST_HEAD_INIT(volume_list);


/*
 * Should the path check be the least sized path? Is that enough to check for nesting?
 */

static struct nexus_volume *
__get_volume(char * path)
{
    struct nexus_volume * vol = NULL;
    struct nexus_volume * tmp = NULL;

    list_for_each_entry(tmp, &volume_list, node) {
	NEXUS_DEBUG("checking volume (%s)\n", tmp->path);
	NEXUS_DEBUG("Comparing with (%s)\n", path);


	if ((strncmp(tmp->path, path, strlen(tmp->path)) == 0)
		&& (tmp->is_online == 1)) {

            NEXUS_DEBUG("Matched Volume paths\n");

            if (kref_get_unless_zero(&(tmp->refcount)) == 0) {
                break;
            }

            vol = tmp;

            break;
        }
    }

    return vol;
}

struct nexus_volume *
nexus_get_volume(char * path)
{
    struct nexus_volume * vol = NULL;
    unsigned long flags;


    spin_lock_irqsave(&volume_list_lock, flags);
    {
	vol = __get_volume(path);
    }
    spin_unlock_irqrestore(&volume_list_lock, flags);

    return vol;
}


static int
register_volume(struct nexus_volume * vol)
{
    unsigned long flags = 0;
    int ret = -1;

    if (!try_module_get(THIS_MODULE)) {
	return -1;
    }

    nexus_printk("Registering Volume at (%s)\n", vol->path);

    spin_lock_irqsave(&volume_list_lock, flags);
    {
	struct nexus_volume * tmp_vol = NULL;

	tmp_vol = __get_volume(vol->path);

	if (tmp_vol != NULL) {
            nexus_put_volume(tmp_vol);
            goto out;
        }

	list_add(&(vol->node), &volume_list);
	ret = 0;
    }
 out:
    spin_unlock_irqrestore(&volume_list_lock, flags);

    if (ret == -1) {
	NEXUS_DEBUG("Volume '%s' exists\n", vol->path);
    }

    return ret;
}


static int
deregister_volume(struct nexus_volume * vol)
{
    unsigned long flags = 0;

    spin_lock_irqsave(&volume_list_lock, flags);
    {
	NEXUS_DEBUG("Deregistering VOLUME '%s'\n", vol->path);
	list_del(&(vol->node));
    }
    spin_unlock_irqrestore(&volume_list_lock, flags);

    return 0;
}


static void
volume_last_put(struct kref * kref)
{
    struct nexus_volume * vol = container_of(kref, struct nexus_volume, refcount);

    /* Abort any pending commands */
    NEXUS_DEBUG("deregistering volume: %s\n", vol->path);

    deregister_volume(vol);

    kfree(vol->path);
    kfree(vol);

    module_put(THIS_MODULE);
}


void
nexus_put_volume(struct nexus_volume * vol)
{
    kref_put(&(vol->refcount), volume_last_put);
}






int
nexus_send_cmd(struct nexus_volume * vol,
	       uint32_t              cmd_len,
	       uint8_t             * cmd_data,
	       uint32_t            * resp_len,
	       uint8_t            ** resp_data)
{
    int ret = 0;

    // acquire vol->cmd_queue mutex
    ret = mutex_lock_interruptible(&(vol->cmd_queue.lock));

    if (ret != 0) {
	NEXUS_ERROR("Command Queue Mutex lock was interrupted...\n");
	goto out2;
    }

    // set data + len
    // mark as active
    vol->cmd_queue.cmd_data  = cmd_data;
    vol->cmd_queue.cmd_len   = cmd_len;
    vol->cmd_queue.resp_len  = 0;
    vol->cmd_queue.resp_data = NULL;

    vol->cmd_queue.active    = 1;

    __asm__ ("":::"memory");

    // wakeup waiting daemon
    wake_up_interruptible(&(vol->cmd_queue.daemon_waitq));

    // wait on kernel waitq until cmd is complete
    // ...Eh fuck it, lets just burn the cpu
    while (vol->cmd_queue.complete == 0) {

	if (vol->is_online == 0) {
            NEXUS_ERROR("daemon is offline\n");
            // remove the volume here
            nexus_put_volume(vol);

            ret = -1;
            goto out1;
        }

	schedule();
    }

    __asm__ ("":::"memory");


    if (vol->cmd_queue.error == 1) {
	ret = -1;

	goto out1;
    }

    // copy resp len/data ptrs
    *resp_len  = vol->cmd_queue.resp_len;
    *resp_data = vol->cmd_queue.resp_data;

    // reset vol->cmd_queue
    vol->cmd_queue.active    = 0;
    vol->cmd_queue.complete  = 0;

 out1:

    // release mutex
    mutex_unlock(&(vol->cmd_queue.lock));

 out2:

    return ret;
}

static ssize_t
volume_read(struct file * filp, char __user * buf, size_t count, loff_t * f_pos)
{
    struct nexus_volume * vol = filp->private_data;

    NEXUS_DEBUG("Read of size %lu\n", count);


    if ((vol->cmd_queue.active   == 0) ||
	(vol->cmd_queue.complete == 1)) {
	return 0;
    }

    if (count == 0) {
	return vol->cmd_queue.cmd_len;
    }

    if (count < vol->cmd_queue.cmd_len) {
	return -EINVAL;
    }

    copy_to_user(buf, vol->cmd_queue.cmd_data, vol->cmd_queue.cmd_len);

    return vol->cmd_queue.cmd_len;
}

static ssize_t
volume_write(struct file * filp, const char __user * buf, size_t count, loff_t * f_pos)
{
    struct nexus_volume * vol = filp->private_data;

    uint8_t * resp = NULL;
    int       ret  = 0;

    NEXUS_DEBUG("Write of Size %lu\n", count);

    if ((vol->cmd_queue.active   == 0) ||
	(vol->cmd_queue.complete == 1)) {
	return 0;
    }


    // check size of resp
    // too large: set error flag in cmd_queue, mark cmd_queue complete, and return -EINVAL
    if (count > MAX_CMD_RESP_SIZE) {
	return -EINVAL;
    }


    // kmalloc buffer for resp
    resp = kmalloc(count, GFP_KERNEL);

    if (IS_ERR(resp)) {
	NEXUS_ERROR("Could not allocate kernel memory for response (count=%lu)\n", count);
	return -ENOMEM;
    }

    // copy_from_user
    ret = copy_from_user(resp, buf, count);

    NEXUS_DEBUG("Write copy_from_user returned %d\n", ret);

    if (ret) {
	NEXUS_ERROR("Could not copy response from userspace\n");
	return -EFAULT;
    }

    // set resp fields in cmd_queue
    vol->cmd_queue.resp_data = resp;
    vol->cmd_queue.resp_len  = count;

    __asm__ ("":::"memory");

    // mark cmd_queue as complete
    vol->cmd_queue.complete  = 1;

    // return count;
    return count;
}

static unsigned int
volume_poll(struct file * filp, struct poll_table_struct * poll_tb)
{
    struct nexus_volume * vol = filp->private_data;

    unsigned int  mask = POLLIN | POLLRDNORM;

    poll_wait(filp, &(vol->cmd_queue.daemon_waitq), poll_tb);

    if ((vol->cmd_queue.active   == 1) &&
	(vol->cmd_queue.complete == 0)) {
	return mask;
    }

    return 0;
}

static int
volume_release(struct inode * inode, struct file * filp)
{
    struct nexus_volume * vol = filp->private_data;

    NEXUS_DEBUG("Release Volume (%s)\n", vol->path);
    vol->is_online = 0;

    nexus_put_volume(vol);

    return 0;
}



static struct file_operations vol_fops = {
    .read    = volume_read,
    .write   = volume_write,
    .poll    = volume_poll,
    .release = volume_release,
};


static int
init_cmd_queue(struct nexus_volume * vol)
{
    init_waitqueue_head(&(vol->cmd_queue.daemon_waitq));

    mutex_init(&(vol->cmd_queue.lock));

    return 0;
}


int
create_nexus_volume(char * path)
{
    struct nexus_volume * vol = NULL;

    int vol_fd = 0;
    int ret    = 0;


    vol = nexus_kmalloc(sizeof(struct nexus_volume), GFP_KERNEL);

    if (vol == NULL) {
	NEXUS_ERROR("Could not allocate Nexus Volume state for (%s)\n", path);
	goto err1;
    }

    memset(vol, 0, sizeof(struct nexus_volume));

    vol->path = kstrdup(path, GFP_KERNEL);

    if (vol->path == NULL) {
	nexus_kfree(vol);
	goto err2;
    }

    init_cmd_queue(vol);

    kref_init(&(vol->refcount));


    // Insert volume into active list
    ret = register_volume(vol);

    if (ret != 0) {
	NEXUS_ERROR("Failed to register Volume\n");
	goto err3;
    }


    vol_fd = anon_inode_getfd("nexus-volume", &vol_fops, vol, O_RDWR);

    if (vol_fd < 0) {
	NEXUS_ERROR("Could not create volume inode\n");
	goto err4;
    }

    vol->is_online = 1;

    return vol_fd;

 err4:
    deregister_volume(vol);
 err3:
    nexus_kfree(vol->path);
 err2:
    nexus_kfree(vol);

 err1:
    return -1;
}


