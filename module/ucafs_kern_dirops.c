#include "ucafs_module.h"

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

    if (ucafs_vnode_path(avc, &path) || is_md_file(name, strlen(name))) {
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
        ERROR("parsing shadow_name failed (type=%d)\n", (int)type);
        goto out;
    }

    /* XXX create: should create remove the match? */
    if (msg_type == UCAFS_MSG_REMOVE) {
        // remove it from the cache
        remove_shdw_name(*shadow_name);
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
    char * fname = NULL;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;
    caddr_t payload;

    // check if it's in the cache
    if ((fname = lookup_shdw_name(shadow_name))) {
        *real_name = fname;
        return 0;
    }

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

    /* add it to the cache */
    add_path_to_cache(shadow_name, parent_dir, *real_name);

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
    int ret = -1, code, len1 = strlen(oldname), len2 = strlen(newname);
    char *from_path = NULL, *to_path = NULL;
    caddr_t payload;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;

    if (is_md_file(oldname, len1) || is_md_file(newname, len2)) {
        return -1;
    }

    if (ucafs_vnode_path(from_vnode, &from_path) ||
        ucafs_vnode_path(to_vnode, &to_path)) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        goto out;
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

    remove_path_name(from_path, oldname);
    remove_path_name(to_path, newname);

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
    if (!xdr_string(&xdrs, &path, UCAFS_PATH_MAX) || !xdr_int(&xdrs, &len) ||
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

int
ucafs_kern_access(struct vcache * avc, afs_int32 rights)
{
    // by default, access is always granted
    int ret = 0, code, is_dir = (vType(avc) == VDIR);
    char * path = NULL;
    caddr_t payload;
    XDR xdrs, *xdr_reply;
    reply_data_t * reply = NULL;

    // if it's a lookup, just return it's ok
    if (rights == ACL_LOOKUP || (is_dir && rights == ACL_READ)) {
        return 0;
    }

    if (ucafs_vnode_path(avc, &path)) {
        return 0;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(path);
        return 0;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    if (!xdr_string(&xdrs, &path, UCAFS_PATH_MAX) || !xdr_int(&xdrs, &rights) ||
        !xdr_int(&xdrs, &is_dir)) {
        READPTR_UNLOCK();
        ERROR("xdr kern access failed\n");
        goto out;
    }

    if (ucafs_mod_send(UCAFS_MSG_CHECKACL, &xdrs, &reply, &code) || code) {
        ERROR("xdr setacl (%s) FAILED\n", path);
        goto out;
    }

    /* read in the response into ret */
    xdr_reply = &reply->xdrs;
    if (!xdr_int(xdr_reply, &ret)) {
        ERROR("reading response fails");
        goto out;
    }

out:
    if (reply) {
        kfree(reply);
    }

    if (path) {
        kfree(path);
    }

    return ret;
}
