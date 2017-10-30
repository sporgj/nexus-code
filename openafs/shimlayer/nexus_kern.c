#include "nexus_module.h"

#include <linux/dcache.h>
#include <linux/list.h>
#include <linux/string.h>

#define PATH_CACHE_CAPACITY 64

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "nexus_kern: " fmt, ##args)

#define SGX_PATH "sgx"
#define SGX_PATHLEN 3

static const char * afs_prefix = "/afs";
static const uint32_t afs_prefix_len = 4;

LIST_HEAD(_watchlist), *watchlist_ptr = &_watchlist;

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre), lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

int
add_path_to_watchlist(const char * path)
{
    watch_path_t * curr;
    int len;

    list_for_each_entry(curr, watchlist_ptr, list)
    {
        if (strncmp(curr->afs_path, path, curr->path_len) == 0) {
            return 0;
        }
    }

    /* if we are here, we need to add the entry to the list */
    len = strnlen(path, NEXUS_PATH_MAX);
    curr = (watch_path_t *)kzalloc(sizeof(watch_path_t) + len, GFP_KERNEL);
    if (curr == NULL) {
        ERROR("allocation error, cannot add path to list");
        return -1;
    }

    curr->path_len = len;
    if (startsWith(afs_prefix, path)) {
        strncpy(curr->afs_path, path + afs_prefix_len, len - afs_prefix_len);
    }

    list_add(&curr->list, watchlist_ptr);

    return 0;
}

void
clear_watchlist(void)
{
    watch_path_t *curr_wp, *prev_wp;

    list_for_each_entry_safe(curr_wp, prev_wp, watchlist_ptr, list)
    {
        list_del(&curr_wp->list);
        kfree(curr_wp);
    }

    INIT_LIST_HEAD(watchlist_ptr);
}

int
NEXUS_DISCONNECTED()
{
    return NEXUS_IS_OFFLINE;
}

// a dummy buffer that checks if a dentry path is in the watchlist
static char path_buf[4096];
static size_t path_buf_len = sizeof(path_buf);
static DEFINE_MUTEX(path_buf_mutex);

int
nexus_kern_init(void)
{
    mutex_init(&path_buf_mutex);

    return 0;
}

static int
d_is_subdir(const struct dentry * dentry)
{
    struct dentry *d = (struct dentry *)dentry, *parent;

    while (!IS_ROOT(d)) {
        parent = d->d_parent;
        prefetch(parent);

        /* check if the names match */
        if (d->d_name.len == SGX_PATHLEN &&
                memcmp(d->d_name.name, SGX_PATH, SGX_PATHLEN) == 0) {
            return 1;
        }

        d = parent;
    }

    return 0;
}

int
nexus_dentry_path(const struct dentry * dentry, char ** dest)
{
    int len = 0;
    int total_len = 0;
    char *path, *result, *buf;
    watch_path_t * curr_entry;

    if (dentry == NULL || d_is_special(dentry) || !d_is_subdir(dentry)) {
        return 1;
    }

    buf = path_buf;

    /* TODO cache the inode number
    printk(KERN_ERR "\npar=%p, dentry=%p, iname=%s d_name.len=%d
    dentry_name=%s",
           dentry->d_parent, dentry, dentry->d_iname, dentry->d_name.len,
           dentry->d_name.name); */

    mutex_lock(&path_buf_mutex);
    path = dentry_path_raw((struct dentry *)dentry, buf, path_buf_len);

    if (IS_ERR_OR_NULL(path)) {
        print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf,
                       sizeof(buf), 1);

        mutex_unlock(&path_buf_mutex);
        return 1;
    }

    list_for_each_entry(curr_entry, watchlist_ptr, list)
    {
        if (startsWith(curr_entry->afs_path, path) && dest) {
            len = strlen(path);

            total_len = afs_prefix_len + len;
            result = kmalloc(total_len + 1, GFP_KERNEL);
            memcpy(result, afs_prefix, afs_prefix_len);
            memcpy(result + afs_prefix_len, path, len);
            result[total_len] = '\0';
            *dest = result;

            mutex_unlock(&path_buf_mutex);
            return 0;
        }
    }

    mutex_unlock(&path_buf_mutex);
    return 1;
}

int
nexus_vnode_path(const struct vcache * avc, char ** dest)
{
    int ret = -1;
    struct dentry * dentry;

    if (avc == NULL || vnode_type(avc) == NEXUS_ANY) {
        return -1;
    }

    /* this calls a dget(dentry) */
    dentry = d_find_alias(AFSTOV((struct vcache *)avc));
    /* maybe check that the dentry is not disconnected? */
    ret = nexus_dentry_path(dentry, dest);

    dput(dentry);

    return ret;
}

void
nexus_kern_ping(void)
{
    static int num = 0;
    int err, code;
    XDR xdrs;
    reply_data_t * reply = NULL;
    caddr_t payload;

    if ((payload = READPTR_TRYLOCK()) == 0) {
        return;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_int(&xdrs, &num)) {
        ERROR("xdr_int failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    num++;

    if (nexus_mod_send(AFS_OP_PING, &xdrs, &reply, &code) || code) {
        num--;
        goto out;
    }

    err = 0;
out:
    if (reply) {
        kfree(reply);
    }
}

