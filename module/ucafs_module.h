
struct ucafs_mod {
    wait_queue_head_t outq, msgq;
    size_t buffersize;
    char * outb, * inb;
    size_t outb_len, inb_len, outb_sent;
    struct task_struct * daemon;
    struct cdev cdev;
    struct mutex send_mut;
};
