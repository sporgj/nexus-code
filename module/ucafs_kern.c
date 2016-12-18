#include "ucafs_mod.h"

int
send_request(ucrpc_msg_t * req, ucrpc_msg_t ** rsp)
{
    mid_t id = req->msg_id;
    ucrpc_msg_t * msg;
    int err = -1, msg_len = MSG_SIZE(req);

    /* get the read buffer */
    if (mutex_lock_interruptible(&dev->mut)) {
        printk(KERN_ERR "mutex_lock_interruptible failed\n");
        return -1;
    }

    if (dev->daemon_pid == 0) {
        mutex_unlock(&dev->mut);
        return -1;
    }

    /* send the message */
    memcpy(dev->outb, req, msg_len);
    dev->avail_read += msg_len;

    while (1) {
        DEFINE_WAIT(wait);
        if (dev->daemon_pid == 0) {
            printk(KERN_ERR "process is offline :(");
            break;
        }

        mutex_unlock(&dev->mut);
        wake_up_interruptible(&dev->rq);

        /* sleep the kernel thread */
        prepare_to_wait(&dev->kq, &wait, TASK_INTERRUPTIBLE);

        if (dev->avail_write == dev->buffersize) {
            schedule();
        }

        finish_wait(&dev->kq, &wait);

        /* now read the buffer */
        if (mutex_lock_interruptible(&dev->mut)) {
            printk(KERN_ERR "mutex_lock_interruptible failed\n");
            return -1;
        }

        msg = (ucrpc_msg_t *)dev->inb;
        if (msg->ack_id == id) {
            dev->avail_write += MSG_SIZE(msg);
            err = 0;
            break;
        }
    }

    mutex_unlock(&dev->mut);
    return err;
}

void
ucafs_kern_ping(void)
{
    ucrpc_msg_t *rsp, msg = {.type = UCAFS_MSG_PING,
                             .msg_id = ucrpc__genid(),
                             .ack_id = 0,
                             .len = 0};
    if (send_request(&msg, &rsp)) {
        printk(KERN_ERR "error with the request\n");
    }

    printk(KERN_INFO "Got response\n");
}
