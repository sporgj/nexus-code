#include "internal.h"

struct fs_manager *
fs_manager_init()
{
    struct fs_manager * manager = nexus_malloc(sizeof(struct fs_manager));

    INIT_LIST_HEAD(&manager->fs_ops_list);

    return manager;
}

struct nexus_fsop_req *
fs_create_op(struct fs_manager * fs_manager, fs_op_type_t type)
{
    struct nexus_fsop_req * req = NULL;

    {
        req = nexus_malloc(sizeof(struct nexus_fsop_req));

        req->req_id          = fs_manager->fs_ops_counter;
        req->type            = type;
        req->fs_manager      = fs_manager;
        req->dirent_requests = nexus_ringbuf_create(sizeof(struct nexus_dirent_req),
                                                    MAX_DIRENT_REQUESTS);
    }


    list_add(&req->node, &manager->fs_ops_list);

    fs_manager->fs_ops_counter += 1;
    fs_manager->fs_ops_len += 1;

    return req;
}

static int
__process_dirent_requests(struct nexus_fsop * req)
{
    struct nexus_dirent_req dirent_req;

    struct fs_dentry * parent_dentry = req->fs_manager->root_dentry;

    int ret = -1;

    // let's deque the first dirent and update the root dentry
    if (!nexus_ringbuf_dequeue(req->dirent_requests, &dirent_req)) {
        log_error("could not deque the root dentry\n");
        return -1;
    }

    namei_touch_dentry(parent_dentry, &dirent_req->uuid);


    // now populate the children
    while (nexus_ringbuf_dequeue(req->dirent_requests, &dirent_req)) {
        struct fs_dentry * dentry = NULL;

        dentry = __namei_touch_dentry(parent_dentry, dirent_req.dirent.name, &dirent_req.uuid);

        if (dentry == NULL) {
            log_error("could not touch dentry for (%s)\n", dirent_req.dirent.name);
            return -1;
        }

        parent_dentry = dentry;
    }

    return 0;
}

int
fs_process_op(struct nexus_fsop_req * req)
{
    int ret = -1;

    if (req->dirent_requests->item_count > 0) {
       ret = __process_dirent_requests(req);

       if (ret) {
           log_error("error processing dirent request\n");
           goto out;
       }
    }

out:
    {
        list_del(&req->node);
        nexus_ringbuf_destroy(req->dirent_requests);
        nexus_free(req);
    }

    return ret;
}
