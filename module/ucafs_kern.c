#include "ucafs_module.h"

#include <linux/list.h>
#include <linux/string.h>

#define PATH_CACHE_CAPACITY 64

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_kern: " fmt, ##args)

static const char * afs_prefix = "/afs";
static const uint32_t afs_prefix_len = 4;

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre), lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

LIST_HEAD(_watchlist), *watchlist_ptr = &_watchlist;

typedef struct {
    char *shdw_name, *parent_path, *fname;
    struct list_head list;
} cached_path_t;

// for the list of all the paths stored
LIST_HEAD(_pathlist), *pathlist_ptr = &_pathlist;
static size_t path_cache_size = 0;

static inline void
free_cache_entry(cached_path_t * curr)
{
    kfree(curr->shdw_name);
    kfree(curr->parent_path);
    kfree(curr->fname);
    kfree(curr);
}

#if 0
// copied from linux/.../scripts/basic/fixdep.c
static unsigned int strhash(const char * str, unsigned int sz)
{
    /* fnv32 hash */
    unsigned int i, hash = 2166136251U;

    for (i = 0; i < sz; i++)
        hash = (hash ^ str[i]) * 0x01000193;
    return hash;
}
#endif

void
add_path_to_cache(const char * shadow_name,
                  const char * parent_path,
                  const char * fname)
{
    cached_path_t * cached_file;
    struct list_head * last_el = pathlist_ptr->prev;

    /* lets make sure we still have page in our cache */
    if (path_cache_size == PATH_CACHE_CAPACITY) {
        list_del(last_el);
        free_cache_entry(list_entry(last_el, cached_path_t, list));
        path_cache_size--;
    }

    cached_file = (cached_path_t *)kmalloc(sizeof(cached_path_t), GFP_KERNEL);
    if (cached_file == NULL) {
        return;
    }

    cached_file->shdw_name =
        (char *)kstrndup(shadow_name, UCAFS_FNAME_MAX, GFP_KERNEL);
    cached_file->parent_path =
        (char *)kstrndup(parent_path, UCAFS_PATH_MAX, GFP_KERNEL);
    cached_file->fname = (char *)kstrndup(fname, UCAFS_FNAME_MAX, GFP_KERNEL);

    if (!cached_file->shdw_name || !cached_file->parent_path ||
        !cached_file->fname) {
        ERROR("!cached_file->shdw_name || !cached_file->plain_path\n");
        return;
    }

    list_add(&cached_file->list, pathlist_ptr);
    path_cache_size++;
}

void
remove_shdw_name(const char * shadow_name)
{
    cached_path_t * curr;

    list_for_each_entry(curr, pathlist_ptr, list)
    {
        if (strncmp(curr->shdw_name, shadow_name, UCAFS_FNAME_MAX)) {
            continue;
        }

        list_del(&curr->list);
        free_cache_entry(curr);
        path_cache_size--;
        break;
    }
}

void
remove_path_name(const char * parent_path, const char * fname)
{
    cached_path_t * curr;

    list_for_each_entry(curr, pathlist_ptr, list)
    {
        if (strncmp(curr->fname, fname, UCAFS_FNAME_MAX) ||
            strncmp(curr->parent_path, parent_path, UCAFS_PATH_MAX)) {
            continue;
        }

        list_del(&curr->list);
        free_cache_entry(curr);
        path_cache_size--;
        break;
    }
}

void
clear_pathlist_cache(void)
{
    cached_path_t * curr;

    list_for_each_entry(curr, pathlist_ptr, list)
    {
        list_del(&curr->list);
        free_cache_entry(curr);
        path_cache_size--;
    }
}

char *
lookup_shdw_name(const char * shadow_name)
{
    cached_path_t * curr;

    list_for_each_entry(curr, pathlist_ptr, list)
    {
        if (strncmp(curr->shdw_name, shadow_name, UCAFS_FNAME_MAX)) {
            continue;
        }

        return kstrdup(curr->fname, GFP_KERNEL);
    }

    return NULL;
}

char *
lookup_path_name(const char * parent_path, const char * fname)
{
    cached_path_t * curr;

    list_for_each_entry(curr, pathlist_ptr, list)
    {
        if (strncmp(curr->fname, fname, UCAFS_FNAME_MAX) ||
            strncmp(curr->parent_path, parent_path, UCAFS_PATH_MAX)) {
            continue;
        }

        return kstrdup(curr->shdw_name, GFP_KERNEL);
    }

    return NULL;
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
    len = strnlen(path, UCAFS_PATH_MAX);
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
UCAFS_DISCONNECTED()
{
    return UCAFS_IS_OFFLINE;
}

static char path_buf[4096];
static size_t path_buf_len = sizeof(path_buf);
static DEFINE_MUTEX(path_buf_mutex);

int
ucafs_kern_init(void)
{
    mutex_init(&path_buf_mutex);

    return 0;
}

int
ucafs_dentry_path(const struct dentry * dentry, char ** dest)
{
    int len, total_len;
    char *path, *result, *buf;
    watch_path_t * curr_entry;

    if (dentry == NULL || d_is_special(dentry)) {
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

    /*
    printk(KERN_ERR "path=%p\n", path);
    print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf, sizeof(buf),
                   1); */

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
ucafs_vnode_path(const struct vcache * avc, char ** dest)
{
    int ret = -1;
    struct dentry * dentry;

    if (avc == NULL || vnode_type(avc) == UC_ANY) {
        return -1;
    }

    /* this calls a dget(dentry) */
    dentry = d_find_alias(AFSTOV((struct vcache *)avc));
    /* maybe check that the dentry is not disconnected? */
    ret = ucafs_dentry_path(dentry, dest);
    dput(dentry);

    return ret;
}

void
ucafs_kern_ping(void)
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

    /* send eveything */
    if (ucafs_mod_send(UCAFS_MSG_PING, &xdrs, &reply, &code) || code) {
        num--;
        goto out;
    }

    err = 0;
out:
    if (reply) {
        kfree(reply);
    }
}

