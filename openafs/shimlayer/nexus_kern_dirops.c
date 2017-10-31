#include "nexus_module.h"

/**
 * Refactored function that is called by create, remove, lookup etc.
 * @param 
 */
static int
__nexus_dirpath_name_afs_op(afs_op_type_t       afs_op_type,
                            struct vcache *     avc,
                            char *              name,
                            nexus_fs_obj_type_t type,
                            char **             shadow_name)
{

    int ret  = -1;
    int code = 0;

    XDR   xdrs;
    XDR * xdr_reply = NULL;

    struct nx_daemon_rsp * reply = NULL;
    char *                 path  = NULL;
    caddr_t                global_outbuffer;

    *shadow_name = NULL;

    // sometimes, AFS tries to create special files...
    if ((name[0] == '\\') || (nexus_vnode_path(avc, &path)) != 0) {
        return -1;
    }

    // acquires the message lock
    global_outbuffer = READPTR_LOCK();

    if (global_outbuffer == 0) {
        kfree(path);
        return -1;
    }

    xdrmem_create(&xdrs, global_outbuffer, READPTR_BUFLEN(), XDR_ENCODE);

    if ((xdr_string(&xdrs, &path, NEXUS_PATH_MAX) == FALSE)
        || (xdr_string(&xdrs, &name, NEXUS_FNAME_MAX) == FALSE)
        || (xdr_int(&xdrs, (int *)&type) == FALSE)) {

        ERROR("xdr create failed (path=%s, type=%d, name=%s)\n",
              path,
              (int)afs_op_type,
              name);

        READPTR_UNLOCK();

        goto out;
    }

    ret = nexus_mod_send(afs_op_type, &xdrs, &reply, &code);

    if ((ret == -1) || (code != 0)) {
        goto out;
    }

    /* read the response */
    xdr_reply = &reply->xdrs;

    if (!xdr_string(xdr_reply, shadow_name, NEXUS_FNAME_MAX)) {
        ERROR("parsing shadow_name failed (type=%d)\n", (int)type);
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
nexus_kern_create(struct vcache *     avc,
                  char *              name,
                  nexus_fs_obj_type_t type,
                  char **             shadow_name)
{
    return __nexus_dirpath_name_afs_op(
        AFS_OP_CREATE, avc, name, type, shadow_name);
}

int
nexus_kern_lookup(struct vcache *     avc,
                  char *              name,
                  nexus_fs_obj_type_t type,
                  char **             shadow_name)
{
    return __nexus_dirpath_name_afs_op(
        AFS_OP_LOOKUP, avc, name, type, shadow_name);
}

int
nexus_kern_remove(struct vcache *     avc,
                  char *              name,
                  nexus_fs_obj_type_t type,
                  char **             shadow_name)
{
    return __nexus_dirpath_name_afs_op(
        AFS_OP_REMOVE, avc, name, type, shadow_name);
}

int
nexus_kern_symlink(struct dentry * dp, char * target, char ** dest)
{
    struct nx_daemon_rsp * reply     = NULL;
    caddr_t                global_outbuffer   = NULL;
    char *                 from_path = NULL;
    XDR *                  xdr_reply = NULL;
    XDR                    xdrs;

    int code = 0;
    int ret  = -1;

    *dest = NULL;

    /* get the path to the dentry */
    if (nexus_dentry_path(dp, &from_path)) {
        goto out;
    }

    global_outbuffer = READPTR_LOCK();
    if (global_outbuffer == 0) {
        kfree(from_path);
        return -1;
    }

    xdrmem_create(&xdrs, global_outbuffer, READPTR_BUFLEN(), XDR_ENCODE);

    if ((xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX) == FALSE)
        || (xdr_string(&xdrs, &target, NEXUS_FNAME_MAX) == FALSE)) {

        ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    if (nexus_mod_send(AFS_OP_SYMLINK, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, dest, NEXUS_FNAME_MAX)) {
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
nexus_kern_hardlink(struct dentry * olddp, struct dentry * newdp, char ** dest)
{
    struct nx_daemon_rsp * reply     = NULL;
    caddr_t                global_outbuffer   = NULL;
    char *                 from_path = NULL;
    char *                 to_path   = NULL;
    XDR *                  xdr_reply = NULL;
    XDR                    xdrs;

    int code = 0;
    int ret  = -1;

    *dest = NULL;

    if ((nexus_dentry_path(olddp, &from_path))
        || (nexus_dentry_path(newdp, &to_path))) {
        goto out;
    }

    global_outbuffer = READPTR_LOCK();
    if (global_outbuffer == 0) {
        kfree(from_path);
        kfree(to_path);

        return -1;
    }

    xdrmem_create(&xdrs, global_outbuffer, READPTR_BUFLEN(), XDR_ENCODE);

    if ((xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX) == FALSE)
        || (xdr_string(&xdrs, &to_path, NEXUS_PATH_MAX) == FALSE)) {

        ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    if (nexus_mod_send(AFS_OP_HARDLINK, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;

    if (xdr_string(xdr_reply, dest, NEXUS_FNAME_MAX) == FALSE) {
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
nexus_kern_filldir(char *              parent_dir,
                   char *              shadow_name,
                   nexus_fs_obj_type_t type,
                   char **             real_name)
{
    // char * fname;
    struct nx_daemon_rsp * reply   = NULL;
    caddr_t                global_outbuffer = NULL;
    XDR *                  xdr_reply;
    XDR                    xdrs;

    int code = 0;
    int err  = -1;

    global_outbuffer = READPTR_LOCK();
    if (global_outbuffer == 0) {
        return -1;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, global_outbuffer, READPTR_BUFLEN(), XDR_ENCODE);

    if ((xdr_string(&xdrs, &parent_dir, NEXUS_PATH_MAX) == FALSE)
        || (xdr_string(&xdrs, &shadow_name, NEXUS_FNAME_MAX) == FALSE)
        || (xdr_int(&xdrs, (int *)&type) == FALSE)) {

        ERROR("xdr filldir failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    /* send eveything */
    if (nexus_mod_send(AFS_OP_FILLDIR, &xdrs, &reply, &code) || code) {
        goto out;
    }

    /* read the response */
    xdr_reply = &reply->xdrs;

    if (xdr_string(xdr_reply, real_name, NEXUS_FNAME_MAX) == FALSE) {
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
nexus_kern_rename(struct vcache * from_vnode,
                  char *          oldname,
                  struct vcache * to_vnode,
                  char *          newname,
                  char **         old_shadowname,
                  char **         new_shadowname)
{
    struct mutex *         rename_mutex = NULL;
    struct nx_daemon_rsp * reply        = NULL;
    caddr_t                global_outbuffer      = NULL;
    XDR *                  xdr_reply    = NULL;
    XDR                    xdrs;

    char * from_path = NULL;
    char * to_path   = NULL;

    int unlocked = 0;
    int code     = 0;
    int ret      = -1;

    if (nexus_vnode_path(from_vnode, &from_path)
        || nexus_vnode_path(to_vnode, &to_path)) {
        goto out;
    }

    global_outbuffer = READPTR_LOCK();
    if (global_outbuffer == 0) {
        goto out;
    }

    xdrmem_create(&xdrs, global_outbuffer, READPTR_BUFLEN(), XDR_ENCODE);

    if ((xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX) == FALSE)
        || (xdr_string(&xdrs, &oldname, NEXUS_FNAME_MAX) == FALSE)
        || (xdr_string(&xdrs, &to_path, NEXUS_PATH_MAX) == FALSE)
        || (xdr_string(&xdrs, &newname, NEXUS_FNAME_MAX) == FALSE)) {

        ERROR("xdr rename failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    /* check if cross directory renaming is present */
    rename_mutex = &AFSTOV(from_vnode)->i_sb->s_vfs_rename_mutex;

    if (mutex_is_locked(rename_mutex)) {
        mutex_unlock(rename_mutex);
        unlocked = 1;
    }

    if (nexus_mod_send(AFS_OP_RENAME, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;

    if ((xdr_string(xdr_reply, old_shadowname, NEXUS_FNAME_MAX) == FALSE)
        || (xdr_string(xdr_reply, new_shadowname, NEXUS_FNAME_MAX) == FALSE)) {

        ERROR("parsing rename response failed\n");
        goto out;
    }

    // remove_path_name(from_path, oldname);
    // remove_path_name(to_path, newname);

    ret = 0;
out:
    if (unlocked) {
        mutex_lock(rename_mutex);
    }

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
nexus_kern_storeacl(struct vcache * avc, AFSOpaque * acl_data)
{
    struct nx_daemon_rsp * reply   = NULL;
    caddr_t                global_outbuffer = NULL;
    char *                 path    = NULL;

    XDR xdrs;

    int code = 0;
    int len  = 0;
    int ret  = -1;

    if (nexus_vnode_path(avc, &path)) {
        return ret;
    }

    global_outbuffer = READPTR_LOCK();
    if (global_outbuffer == 0) {
        kfree(path);
        return -1;
    }

    len = acl_data->AFSOpaque_len;

    xdrmem_create(&xdrs, global_outbuffer, READPTR_BUFLEN(), XDR_ENCODE);

    if ((xdr_string(&xdrs, &path, NEXUS_PATH_MAX) == FALSE)
        || (xdr_int(&xdrs, &len) == FALSE)
        || (xdr_opaque(&xdrs, (caddr_t)acl_data->AFSOpaque_val, len)
            == FALSE)) {

        ERROR("xdr storeacl failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    if (nexus_mod_send(AFS_OP_STOREACL, &xdrs, &reply, &code) || code) {
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
