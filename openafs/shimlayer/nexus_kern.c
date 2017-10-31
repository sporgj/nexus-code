#include "nexus_module.h"

#include <linux/dcache.h>
#include <linux/list.h>
#include <linux/string.h>

static const char *   AFS_PREFIX     = "/afs";
static const uint32_t AFS_PREFIX_LEN = 4;

/* the list of all paths watched */
LIST_HEAD(nexus_volumes_head);

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre);
    size_t lenstr = strlen(str);

    return (lenstr < lenpre) ? 0 : (strncmp(pre, str, lenpre) == 0);
}

int
nexus_add_volume(const char * path)
{
    struct nexus_volume_path * curr = NULL;
    int                        len  = strnlen(path, NEXUS_PATH_MAX);

    list_for_each_entry(curr, &nexus_volumes_head, list)
    {
        if (strncmp(curr->afs_path, path, curr->path_len) == 0) {
            return 0;
        }
    }

    /* if we are here, we need to add the entry to the list */
    curr = (struct nexus_volume_path *)kzalloc(
        sizeof(struct nexus_volume_path) + len, GFP_KERNEL);
    if (curr == NULL) {
        NEXUS_ERROR("allocation error, cannot add path to list");
        return -1;
    }

    curr->path_len = len;

    /* we should allow for paths that do not contain '/afs' */
    if (startsWith(AFS_PREFIX, path)) {
        strncpy(curr->afs_path, path + AFS_PREFIX_LEN, len - AFS_PREFIX_LEN);
    } else {
        strncpy(curr->afs_path, path, len);
    }

    list_add(&curr->list, &nexus_volumes_head);

    return 0;
}

void
nexus_clear_volume_list(void)
{
    struct nexus_volume_path * curr_wp = NULL;
    struct nexus_volume_path * prev_wp = NULL;

    list_for_each_entry_safe(curr_wp, prev_wp, &nexus_volumes_head, list)
    {
        list_del(&curr_wp->list);
        kfree(curr_wp);
    }

    INIT_LIST_HEAD(&nexus_volumes_head);
}

int
NEXUS_DISCONNECTED()
{
    return NEXUS_IS_OFFLINE;
}

// a dummy buffer that checks if a dentry path is in the watchlist
static char   path_buf[4096];
static size_t path_buf_len = sizeof(path_buf);
static DEFINE_MUTEX(path_buf_mutex);

int
nexus_kern_init(void)
{
    mutex_init(&path_buf_mutex);

    return 0;
}

int
nexus_dentry_path(const struct dentry * dentry, char ** dest)
{
    int                        len        = 0;
    int                        total_len  = 0;
    char *                     path       = NULL;
    char *                     result     = NULL;
    char *                     buf        = NULL;
    struct nexus_volume_path * curr_entry = NULL;

    if (dentry == NULL || d_is_special(dentry)) {
        return 1;
    }

    buf = path_buf;

    mutex_lock(&path_buf_mutex);
    path = dentry_path_raw((struct dentry *)dentry, buf, path_buf_len);

    if (IS_ERR_OR_NULL(path)) {
        print_hex_dump(
            KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf, sizeof(buf), 1);

        mutex_unlock(&path_buf_mutex);
        return 1;
    }

    list_for_each_entry(curr_entry, &nexus_volumes_head, list)
    {
        if (startsWith(curr_entry->afs_path, path) && dest) {
            len = strlen(path);

            total_len = AFS_PREFIX_LEN + len;
            result    = kmalloc(total_len + 1, GFP_KERNEL);
            memcpy(result, AFS_PREFIX, AFS_PREFIX_LEN);
            memcpy(result + AFS_PREFIX_LEN, path, len);
            result[total_len] = '\0';
            *dest             = result;

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
    int             ret = -1;
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
    static int             num = 0;
    int                    err, code;
    XDR                    xdrs;
    struct nx_daemon_rsp * reply = NULL;
    caddr_t                payload;

    if ((payload = READPTR_TRYLOCK()) == 0) {
        return;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_int(&xdrs, &num)) {
        NEXUS_ERROR("xdr_int failed\n");
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
