#include "ucafs_kern.h"
#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_fetch: " fmt, ##args)

int
ucafs_fetch(struct afs_conn * tc,
            struct rx_connection * rxconn,
            struct osi_file * fp,
            afs_size_t base,
            struct dcache * adc,
            struct vcache * avc,
            afs_int32 size,
            struct afs_FetchOutput * tsmall)
{
    int ret = AFSX_STATUS_NOOP, start_pos, end_pos;
	fetch_context * context;

    if (!UCAFS_IS_CONNECTED || vType(avc) == VDIR) {
        return ret;
    }

    if (__is_vnode_ignored(avc, &path)) {
        return ret;
    }

    /* create the context */
    context = (fetch_context_t *)kzalloc(sizeof(fetch_context_t), GFP_KERNEL);
    if (context == NULL) {
        ERROR("allocation error on fetch context");
		kfree(path);
        return AFSX_STATUS_ERROR;
    }

	if ((context->buffer = ALLOC_XFER_BUFFER) == NULL) {
		ERROR("context's buffer allocation failed\n");
		goto out;
	}

    context->id = -1;
    context->path = path;
	context->uc_conn = __get_conn();
	context->avc = avc;
	context->tc = tc;
	context->rx_conn = rxconn;

	start_pos = FBOX_CHUNK_BASE(num);
	end_pos = FBOX_CHUNK_BASE(base + size) + UCAFS_CHUNK_SIZE;
	length = end_pos - start_pos;

	/* instantiate the context with the AFS fileserver */

    ret = 0;
out:
	kfree(path);

	if (context->buffer) {
		FREE_XFER_BUFFER(context->buffer);
	}

	kfree(context);

    return ret;
}
