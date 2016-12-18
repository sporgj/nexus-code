#include "ucafs_mod.h"
#include <linux/random.h>

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_kern: " fmt, ##args)

inline caddr_t
READPTR_LOCK(void)
{
    if (mutex_lock_interruptible(&dev->mut)) {
        ERROR("locking mutex failed\n");
        return 0;
    }

    /* clear the message at that pointer */
    memset(dev->outb, 0, sizeof(ucrpc_msg_t));
    return (caddr_t)((char *)dev->outb + sizeof(ucrpc_msg_t));
}

inline void
READPTR_UNLOCK(void)
{
    mutex_unlock(&dev->mut);
}

// hold READPTR_LOCK()
inline size_t
READPTR_BUFLEN(void)
{
    return (dev->buffersize - dev->avail_read - sizeof(ucrpc_msg_t));
}

void
ucafs_kern_ping(void)
{
    int err, num = get_random_int();
    XDR xdrs, * rsp = NULL;
    caddr_t payload;

    if ((payload = READPTR_LOCK()) == 0) {
        return;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_int(&xdrs, &num)) {
        ERROR("xdr_int failed\n");
        goto out;
    }

    /* send eveything */
    if (ucafs_mod_send(UCAFS_MSG_PING, &xdrs, &rsp)) {
        printk(KERN_INFO "filldir failure\n");
        goto out;
    }

    printk(KERN_INFO "Got a response\n");

    err = 0;
out:
    if (rsp) {
        kfree(rsp);
    }
}

int
ucafs_kern_filldir(char * parent_dir, char * shadow_name, char ** real_name)
{
    int err;
    XDR xdrs, * rsp = NULL;
    caddr_t payload;

    if ((payload = READPTR_LOCK()) == 0) {
        return -1;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!(xdr_string(&xdrs, &parent_dir, UCAFS_PATH_MAX)) ||
        !(xdr_string(&xdrs, &shadow_name, UCAFS_FNAME_MAX))) {
        ERROR("xdr filldir failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    /* send eveything */
    if (ucafs_mod_send(UCAFS_MSG_FILLDIR, &xdrs, &rsp)) {
        printk(KERN_INFO "filldir failure\n");
        goto out;
    }

    printk(KERN_INFO "Got a response\n");

    err = 0;
out:
    if (rsp) {
        kfree(rsp);
    }

    return err;
}
