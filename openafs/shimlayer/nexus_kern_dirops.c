#include "nexus_module.h"

static int
__nexus_parent_aname_req(uc_msg_type_t       msg_type,
                         struct vcache    *  avc,
                         char             *  name,
                         nexus_entry_type    type,
                         char             ** shadow_name)
{

    XDR   xdrs;
    XDR * xdr_reply         = NULL;

    reply_data_t * reply    = NULL;
    char         * path     = NULL;
    caddr_t        payload;

    int ret  = -1;
    int code =  0;

    
    *shadow_name = NULL;

    if ((name[0]                       == '\\') ||
	(nexus_vnode_path(avc, &path)) != 0) {
        return -1;
    }


    payload = READPTR_LOCK();

    if (payload == 0) {
        kfree(path);
        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);

    if ( (xdr_string(&xdrs, &path, NEXUS_PATH_MAX)  == FALSE) ||
	 (xdr_string(&xdrs, &name, NEXUS_FNAME_MAX) == FALSE) ||
	 (xdr_int(&xdrs, (int *)&type)              == FALSE) ) {

        ERROR("xdr create failed (path=%s, type=%d, name=%s)\n", path,
              (int)msg_type, name);

	READPTR_UNLOCK();

	goto out;
    }

    ret = nexus_mod_send(msg_type, &xdrs, &reply, &code);
    
    if ( (ret  == -1) ||
	 (code !=  0) ) {
        goto out;
    }

    /* read the response */
    xdr_reply = &reply->xdrs;

    if (!xdr_string(xdr_reply, shadow_name, NEXUS_FNAME_MAX)) {
        ERROR("parsing shadow_name failed (type=%d)\n", (int)type);
        goto out;
    }

    /* XXX create: should create remove the match? */
    if (msg_type == NEXUS_MSG_REMOVE) {
        // remove it from the cache
        //remove_shdw_name(*shadow_name);
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
nexus_kern_create(struct vcache     * avc,
                  char              * name,
                  nexus_entry_type    type,
                  char             ** shadow_name)
{
    return __nexus_parent_aname_req(NEXUS_MSG_CREATE,
				    avc,
				    name,
				    type,
                                    shadow_name);
}

int
nexus_kern_lookup(struct vcache     * avc,
                  char              * name,
                  nexus_entry_type    type,
                  char             ** shadow_name)
{
    return __nexus_parent_aname_req(NEXUS_MSG_LOOKUP,
				    avc,
				    name,
				    type,
                                    shadow_name);
}

int
nexus_kern_remove(struct vcache     * avc,
                  char              * name,
                  nexus_entry_type    type,
                  char             ** shadow_name)
{
    return __nexus_parent_aname_req(NEXUS_MSG_REMOVE,
				    avc,
				    name,
				    type,
                                    shadow_name);
}

int
nexus_kern_symlink(struct dentry  * dp,
		   char           * target,
		   char          ** dest)
{
    reply_data_t * reply      = NULL;
    caddr_t        payload    = NULL;
    char         * from_path  = NULL;
    XDR          * xdr_reply  = NULL;
    XDR            xdrs;

    int code =  0;
    int ret  = -1;

    
    *dest = NULL;

    /* get the path to the dentry */
    if (nexus_dentry_path(dp, &from_path)) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(from_path);
        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    
    if ( (xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX)  == FALSE) ||
	 (xdr_string(&xdrs, &target,    NEXUS_FNAME_MAX) == FALSE) )  {

	ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();

	goto out;
    }

    if (nexus_mod_send(NEXUS_MSG_SYMLINK, &xdrs, &reply, &code) || code) {
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
nexus_kern_hardlink(struct dentry  * olddp,
		    struct dentry  * newdp,
		    char          ** dest)
{
    reply_data_t * reply     = NULL;
    caddr_t        payload   = NULL;
    char         * from_path = NULL;
    char         * to_path   = NULL;
    XDR          * xdr_reply = NULL;
    XDR            xdrs;

    int code  =  0;
    int ret   = -1;
    
    *dest = NULL;

    if ((nexus_dentry_path(olddp, &from_path)) ||
        (nexus_dentry_path(newdp, &to_path))) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(from_path);
        kfree(to_path);

        return -1;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    
    if ( (xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX) == FALSE)  ||
	 (xdr_string(&xdrs, &to_path,   NEXUS_PATH_MAX) == FALSE) ) {

	ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();

	goto out;
    }

    if (nexus_mod_send(NEXUS_MSG_HARDLINK, &xdrs, &reply, &code) || code) {
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
nexus_kern_filldir(char              * parent_dir,
                   char              * shadow_name,
                   nexus_entry_type    type,
                   char             ** real_name)
{
    //char * fname;
    reply_data_t * reply   = NULL;
    caddr_t        payload = NULL;
    XDR          * xdr_reply;
    XDR            xdrs;
    
    int code =  0;
    int err  = -1;
    
    // check if it's in the cache
    /*
    if ((fname = lookup_shdw_name(shadow_name))) {
        *real_name = fname;
        return 0;
    }
    */

    if ((payload = READPTR_LOCK()) == 0) {
        return -1;
    }

    /* create the XDR object */
    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);

    if ( (xdr_string(&xdrs, &parent_dir,  NEXUS_PATH_MAX)  == FALSE) ||
	 (xdr_string(&xdrs, &shadow_name, NEXUS_FNAME_MAX) == FALSE) ||
	 (xdr_int(&xdrs, (int *)&type)                     == FALSE) ) {

	ERROR("xdr filldir failed\n");
        READPTR_UNLOCK();

	goto out;
    }

    /* send eveything */
    if (nexus_mod_send(NEXUS_MSG_FILLDIR, &xdrs, &reply, &code) ||
	code) {
        goto out;
    }

    /* read the response */
    xdr_reply = &reply->xdrs;
    
    if (xdr_string(xdr_reply, real_name, NEXUS_FNAME_MAX) == FALSE) {
        ERROR("parsing shadow_name failed\n");
        goto out;
    }

    /* add it to the cache */
    //add_path_to_cache(shadow_name, parent_dir, *real_name);

    err = 0;
out:
    if (reply) {
        kfree(reply);
    }

    return err;
}

int
nexus_kern_rename(struct vcache  * from_vnode,
                  char           * oldname,
                  struct vcache  * to_vnode,
                  char           * newname,
                  char          ** old_shadowname,
                  char          ** new_shadowname)
{
    struct mutex * rename_mutex = NULL;
    reply_data_t * reply        = NULL;
    caddr_t        payload      = NULL;
    XDR          * xdr_reply    = NULL;
    XDR            xdrs;

    char         * from_path    = NULL;
    char         * to_path      = NULL;

    int unlocked =  0;
    int code     =  0;
    int ret      = -1;

    
    if (nexus_vnode_path(from_vnode, &from_path) ||
        nexus_vnode_path(to_vnode, &to_path)) {
        goto out;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        goto out;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    
    if ( (xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX)  == FALSE) ||
	 (xdr_string(&xdrs, &oldname,   NEXUS_FNAME_MAX) == FALSE) ||
	 (xdr_string(&xdrs, &to_path,   NEXUS_PATH_MAX)  == FALSE) ||
	 (xdr_string(&xdrs, &newname,   NEXUS_FNAME_MAX) == FALSE) ) {
	
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

    if (nexus_mod_send(NEXUS_MSG_RENAME, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;

    if ( (xdr_string(xdr_reply, old_shadowname, NEXUS_FNAME_MAX) == FALSE) ||
	 (xdr_string(xdr_reply, new_shadowname, NEXUS_FNAME_MAX) == FALSE) ) {

	ERROR("parsing rename response failed\n");
        goto out;
    }

    //remove_path_name(from_path, oldname);
    //remove_path_name(to_path, newname);

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

    if (ret &&
	*old_shadowname) {
	
        kfree(*old_shadowname);
        *old_shadowname = NULL;
    }

    return ret;
}

int
nexus_kern_storeacl(struct vcache * avc,
		    AFSOpaque     * acl_data)
{
    reply_data_t * reply   = NULL;
    caddr_t        payload = NULL;
    char         * path    = NULL;

    XDR xdrs;

    int code =  0;
    int len  =  0;
    int ret  = -1;

    if (nexus_vnode_path(avc, &path)) {
        return ret;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(path);
        return -1;
    }

    len = acl_data->AFSOpaque_len;

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    
    if ( (xdr_string(&xdrs, &path, NEXUS_PATH_MAX)                 == FALSE) ||
	 (xdr_int(&xdrs, &len)                                     == FALSE) ||
	 (xdr_opaque(&xdrs, (caddr_t)acl_data->AFSOpaque_val, len) == FALSE) ) {

        ERROR("xdr storeacl failed\n");
        READPTR_UNLOCK();

	goto out;
    }

    if (nexus_mod_send(NEXUS_MSG_STOREACL, &xdrs, &reply, &code) ||
	code) {
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
nexus_kern_access(struct vcache * avc,
		  afs_int32       rights)
{
    reply_data_t * reply     = NULL;
    caddr_t        payload   = NULL;
    char         * path      = NULL;
    XDR          * xdr_reply = NULL;
    XDR            xdrs;
    
    // by default, access is always granted
    int is_dir = (vType(avc) == VDIR);
    int code   = 0;
    int ret    = 0;
 
    // if it's a lookup, just return it's ok
    if ( (rights == ACL_LOOKUP) ||
	 ( (is_dir) &&
	   (rights == ACL_READ) ) ) {
        return 0;
    }

    if (nexus_vnode_path(avc, &path)) {
        return 0;
    }

    if ((payload = READPTR_LOCK()) == 0) {
        kfree(path);
        return 0;
    }

    xdrmem_create(&xdrs, payload, READPTR_BUFLEN(), XDR_ENCODE);
    
    if ( (xdr_string(&xdrs, &path, NEXUS_PATH_MAX)  == FALSE) ||
	 (xdr_int(&xdrs, &rights)                   == FALSE) ||
	 (xdr_int(&xdrs, &is_dir)                   == FALSE ) ) {

        READPTR_UNLOCK();
        ERROR("xdr kern access failed\n");

	goto out;
    }

    if (nexus_mod_send(NEXUS_MSG_CHECKACL, &xdrs, &reply, &code) ||
	code) {
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
