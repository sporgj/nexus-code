#include "ucafs_module.h"

#undef ERROR
#define ERROR(fmt, args...) printk(KERN_ERR "ucafs_kern: " fmt, ##args)

static const char * afs_prefix = "/afs";
static const uint32_t afs_prefix_len = 4;

static char * watch_dirs[] = {UCAFS_PATH_KERN "/" UC_AFS_WATCH};
static const int watch_dir_len[] = {sizeof(watch_dirs[0]) - 1};

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre), lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

LIST_HEAD(_watchlist), *watchlist_ptr = &_watchlist;

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

inline ucafs_entry_type
dentry_type(const struct dentry * dentry)
{
    if (d_is_file(dentry)) {
        return UC_FILE;
    } else if (d_is_dir(dentry)) {
        return UC_DIR;
    } else if (d_is_symlink(dentry)) {
        return UC_LINK;
    }

    return UC_ANY;
}

inline ucafs_entry_type
vnode_type(const struct vcache * vnode)
{
    if (vnode == NULL) {
        return UC_ANY;
    }

    switch (vType(vnode)) {
    case VREG:
        return UC_FILE;
    case VDIR:
        return UC_DIR;
    case VLNK:
        return UC_LINK;
    }

    return UC_ANY;
}

int
ucafs_dentry_path(const struct dentry * dentry, char ** dest)
{
    int len, total_len;
    char *path, *result;
    char buf[512];
    watch_path_t * curr_entry;

    if (dentry == NULL) {
        return 1;
    }

    /* TODO cache the inode number
    printk(KERN_ERR "\npar=%p, dentry=%p, iname=%s d_name.len=%d
    dentry_name=%s",
           dentry->d_parent, dentry, dentry->d_iname, dentry->d_name.len,
           dentry->d_name.name); */
    path = dentry_path_raw((struct dentry *)dentry, buf, sizeof(buf));

    if (IS_ERR_OR_NULL(path)) {
        print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf,
                       sizeof(buf), 1);
        return 1;
    }

    /*
    printk(KERN_ERR "path=%p\n", path);
    print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf, sizeof(buf),
                   1); */

    list_for_each_entry(curr_entry, watchlist_ptr, list)
    {
        if (startsWith(curr_entry->afs_path, path)) {
            if (dest) {
                len = strlen(path);
                total_len = afs_prefix_len + len;
                result = kmalloc(total_len + 1, GFP_KERNEL);
                memcpy(result, afs_prefix, afs_prefix_len);
                memcpy(result + afs_prefix_len, path, len);
                result[total_len] = '\0';
                *dest = result;
            }

            return 0;
        }
    }

    return 1;
}

inline int
ucafs_vnode_path(const struct vcache * avc, char ** dest)
{
    if (avc == NULL || vnode_type(avc) == UC_ANY) {
        return -1;
    }

    return ucafs_dentry_path(d_find_alias(AFSTOV((struct vcache *)avc)), dest);
}

void
ucafs_kern_ping(void)
{
    static int num = 0;
    int err, code;
    XDR xdrs;
    reply_data_t * reply = NULL;
    caddr_t payload;

    if ((payload = READPTR_LOCK()) == 0) {
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

static int
__ucafs_parent_aname_req(uc_msg_type_t msg_type,
                         struct vcache * avc,
                         char * name,
                         ucafs_entry_type type,
                         char ** shadow_name)
{
    int ret = -1, code;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;
    caddr_t payload;
    char * path;

    *shadow_name = NULL;

    if (ucafs_vnode_path(avc, &path)) {
        return -1;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(path);
        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_string(&xdrs, &path, UCAFS_PATH_MAX) ||
        !xdr_string(&xdrs, &name, UCAFS_FNAME_MAX) ||
        !xdr_int(&xdrs, (int *)&type)) {
        ERROR("xdr create failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    if (ucafs_mod_send(msg_type, &xdrs, &reply, &code) || code) {
        goto out;
    }

    /* read the response */
    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, shadow_name, UCAFS_FNAME_MAX)) {
        ERROR("parsing shadow_name failed");
        goto out;
    }

    ret = 0;
out:
    kfree(path);

    if (reply) {
        kfree(reply);
    }

    return ret;
}

int
ucafs_kern_create(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name)
{
    return __ucafs_parent_aname_req(UCAFS_MSG_CREATE, avc, name, type,
                                    shadow_name);
}

int
ucafs_kern_lookup(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name)
{
    return __ucafs_parent_aname_req(UCAFS_MSG_LOOKUP, avc, name, type,
                                    shadow_name);
}

int
ucafs_kern_remove(struct vcache * avc,
                  char * name,
                  ucafs_entry_type type,
                  char ** shadow_name)
{
    return __ucafs_parent_aname_req(UCAFS_MSG_REMOVE, avc, name, type,
                                    shadow_name);
}

int
ucafs_kern_symlink(struct dentry * dp, char * target, char ** dest)
{
    int ret = -1, code;
    char * from_path = NULL;
    caddr_t payload;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;

    *dest = NULL;

    /* get the path to the dentry */
    if (ucafs_dentry_path(dp, &from_path)) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(from_path);
        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_string(&xdrs, &from_path, UCAFS_PATH_MAX) ||
        !xdr_string(&xdrs, &target, UCAFS_FNAME_MAX)) {
        ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    if (ucafs_mod_send(UCAFS_MSG_SYMLINK, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, dest, UCAFS_FNAME_MAX)) {
        ERROR("parsing hardlink name failed\n");
        goto out;
    }

    ret = 0;
out:
    if (reply) {
        kfree(reply);
    }

    if (from_path) {
        kfree(from_path);
    }

    return ret;
}

int
ucafs_kern_hardlink(struct dentry * olddp, struct dentry * newdp, char ** dest)
{
    int ret = -1, code;
    char *from_path = NULL, *to_path = NULL;
    caddr_t payload;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;

    *dest = NULL;

    if (ucafs_dentry_path(olddp, &from_path) ||
        ucafs_dentry_path(newdp, &to_path)) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(from_path);
        kfree(to_path);

        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_string(&xdrs, &from_path, UCAFS_PATH_MAX) ||
        !xdr_string(&xdrs, &to_path, UCAFS_PATH_MAX)) {
        ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    if (ucafs_mod_send(UCAFS_MSG_HARDLINK, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, dest, UCAFS_FNAME_MAX)) {
        ERROR("parsing hardlink name failed\n");
        goto out;
    }

    ERROR("hardlink got; %p vs %p\n", *dest, xdr_reply);

    ret = 0;
out:
    if (from_path) {
        kfree(from_path);
    }

    if (to_path) {
        kfree(to_path);
    }

    if (reply) {
        kfree(reply);
    }

    return ret;
}

int
ucafs_kern_filldir(char * parent_dir,
                   char * shadow_name,
                   ucafs_entry_type type,
                   char ** real_name)
{
    int err = -1, code;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;
    caddr_t payload;

    if ((payload = READPTR_LOCK()) == 0) {
        return -1;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!(xdr_string(&xdrs, &parent_dir, UCAFS_PATH_MAX)) ||
        !(xdr_string(&xdrs, &shadow_name, UCAFS_FNAME_MAX)) ||
        !xdr_int(&xdrs, (int *)&type)) {
        ERROR("xdr filldir failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    /* send eveything */
    if (ucafs_mod_send(UCAFS_MSG_FILLDIR, &xdrs, &reply, &code) || code) {
        goto out;
    }

    /* read the response */
    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, real_name, UCAFS_FNAME_MAX)) {
        ERROR("parsing shadow_name failed\n");
        goto out;
    }

    err = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return err;
}

int
ucafs_kern_rename(struct vcache * from_vnode,
                  char * oldname,
                  struct vcache * to_vnode,
                  char * newname,
                  char ** old_shadowname,
                  char ** new_shadowname)
{
    int ret = -1, code;
    char *from_path = NULL, *to_path = NULL;
    caddr_t payload;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;

    if (ucafs_vnode_path(from_vnode, &from_path) ||
        ucafs_vnode_path(to_vnode, &to_path)) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_string(&xdrs, &from_path, UCAFS_PATH_MAX) ||
        !xdr_string(&xdrs, &oldname, UCAFS_FNAME_MAX) ||
        !xdr_string(&xdrs, &to_path, UCAFS_PATH_MAX) ||
        !xdr_string(&xdrs, &newname, UCAFS_FNAME_MAX)) {
        ERROR("xdr rename failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    if (ucafs_mod_send(UCAFS_MSG_RENAME, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, old_shadowname, UCAFS_FNAME_MAX) ||
        !xdr_string(xdr_reply, new_shadowname, UCAFS_FNAME_MAX)) {
        ERROR("parsing rename response failed\n");
        goto out;
    }

    ret = 0;
out:
    if (from_path) {
        kfree(from_path);
    }

    if (to_path) {
        kfree(to_path);
    }

    if (reply) {
        kfree(reply);
    }

    if (ret && *old_shadowname) {
        kfree(*old_shadowname);
        *old_shadowname = NULL;
    }

    return ret;
}

int
ucafs_kern_storeacl(struct vcache * avc, AFSOpaque * acl_data)
{
    int ret = -1, code, len;
    char * path = NULL;
    caddr_t payload;
    XDR xdrs;
    reply_data_t * reply = NULL;

    if (ucafs_vnode_path(avc, &path)) {
        return ret;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(path);
        return -1;
    }

    len = acl_data->AFSOpaque_len;

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_string(&xdrs, &path, UCAFS_PATH_MAX) ||
        !xdr_int(&xdrs, &len) ||
        !xdr_opaque(&xdrs, (caddr_t)acl_data->AFSOpaque_val, len)) {
        ERROR("xdr storeacl failed\n");
        READPTR_UNLOCK();
        goto out;
    }

    if (ucafs_mod_send(UCAFS_MSG_STOREACL, &xdrs, &reply, &code) || code) {
        ERROR("xdr setacl (%s) FAILED\n", path);
        goto out;
    }

    ret = 0;
out:
    if (path) {
        kfree(path);
    }

    if (reply) {
        kfree(reply);
    }

    return ret;
}
