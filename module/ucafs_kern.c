#include "ucafs_mod.h"

void
ucafs_kern_ping(void)
{
    ucrpc_msg_t msg = {.type = UCAFS_MSG_PING,
                       .msg_id = ucrpc__genid(),
                       .ack_id = 0,
                       .len = 0};
    int msg_len = UCRPC_TLEN(&msg);

    /* get the read buffer */
    if (mutex_lock_interruptible(&dev->mut)) {
        //ERROR("mutex_lock failed\n");
        return;
    }

    memcpy(&dev->outb, &msg, msg_len);
    dev->avail_read = msg_len;
    printk(KERN_INFO "ping message sent\n");
    mutex_unlock(&dev->mut);

    /* now wait on the response */
}
