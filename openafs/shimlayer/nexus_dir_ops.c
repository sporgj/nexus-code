#include <linux/kernel.h>
#include <linux/limits.h>

#include "nexus_module.h"
#include "nexus_json.h"
#include "nexus_util.h"


/* from <linux/limits.h>
 * PATH_MAX ==> Maximum Path Length 
 * NAME_MAX ==> Maximum File Name Length 
 */

static char * 
__get_path(struct vcache * avc)
{
    struct dentry * dentry = NULL;
    char          * path   = NULL;

    int ret = 0;
    
    if ( (avc             == NULL) ||
	 (vnode_type(avc) == NEXUS_ANY) ) {
        return NULL;
    }

    /* this calls a dget(dentry) */
    dentry = d_find_alias(AFSTOV(avc));

    /* maybe check that the dentry is not disconnected? */
    ret = nexus_dentry_path(dentry, &path);

    dput(dentry);

    if (ret != 0) {
	return NULL;
    }
    
    return path;
}





static const char * generic_cmd_str =		\
    "{\n"					\
    "\"op\"   : %d,"     "\n"			\
    "\"name\" : \"%s\"," "\n"			\
    "\"path\" : \"%s\"," "\n"			\
    "\"type\" : %d"      "\n"			\
    "}";


int
nexus_kern_create(struct vcache        * avc,
		  char                 * name,
		  nexus_fs_obj_type_t    type,
		  char                ** nexus_name)
{
    char * cmd_str   = NULL;
    char * path      = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;

    
    if (name[0] == '\\') {
	NEXUS_ERROR("Tried to create strange file (%s)\n", name);
	return -1;
    }

    path = __get_path(avc);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for new file (%s)\n", name);
	ret = -1;
	goto out;
    }
    
    cmd_str = kasprintf(GFP_KERNEL, generic_cmd_str, AFS_OP_CREATE, name, path, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }


    AFS_GUNLOCK();
    ret = nexus_send_cmd(strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    RX_AFS_GLOCK();
    
    if (ret == -1) {
	NEXUS_ERROR("Error Sending Nexus Command\n");
	ret = -1;
	goto out;
    }

    // handle response...
    {
	struct nexus_json_param resp[2] = { {"code",       NEXUS_JSON_S32,    0},
					    {"nexus_name", NEXUS_JSON_STRING, 0} };

	s32 ret_code = 0;
	
	ret = nexus_json_parse(resp_data, resp, 2);
	
	if (ret != 0) {
	    NEXUS_ERROR("Could not parse JSON response\n");
	    ret = -1;
	    goto out;
	}

	ret_code = (s32)resp[0].val;
	
	if (ret_code != 0) {
	    NEXUS_ERROR("User space returned error... (%d)\n", ret_code);
	    ret = -1;
	    goto out;
	}

	*nexus_name = kstrdup((char *)resp[1].val, GFP_KERNEL);	
    }

 out:
    if (path)      nexus_kfree(path);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);
    
    return ret;
}

int
nexus_kern_lookup(struct vcache        * avc,
                  char                 * name,
                  nexus_fs_obj_type_t    type,
                  char                ** nexus_name)
{
    char * cmd_str   = NULL;
    char * path      = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;

    
    if (name[0] == '\\') {
	NEXUS_ERROR("Tried to lookup strange file (%s)\n", name);
	ret = -1;
	goto out;
    }

    path = __get_path(avc);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for file (%s)\n", name);
	ret = -1;
	goto out;
    }
    
    cmd_str = kasprintf(GFP_KERNEL, generic_cmd_str, AFS_OP_LOOKUP, name, path, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    RX_AFS_GLOCK();
    
    
    if (ret == -1) {
	NEXUS_ERROR("Error Sending Nexus Command\n");
	ret = -1;
	goto out;
    }

    // handle response...
    {
	struct nexus_json_param resp[2] = { {"code",       NEXUS_JSON_S32,    0},
					    {"nexus_name", NEXUS_JSON_STRING, 0} };

	s32 ret_code = 0;
	
	ret = nexus_json_parse(resp_data, resp, 2);
	
	if (ret != 0) {
	    NEXUS_ERROR("Could not parse JSON response\n");
	    ret = -1;
	    goto out;
	}

	ret_code = (s32)resp[0].val;
	
	if (ret_code != 0) {
	    NEXUS_ERROR("User space returned error... (%d)\n", ret_code);
	    ret = -1;
	    goto out;
	}

	*nexus_name = kstrdup((char *)resp[1].val, GFP_KERNEL);
    }
    
 out:
    if (path)      nexus_kfree(path);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);

    return ret;
}

int
nexus_kern_remove(struct vcache        * avc,
                  char                 * name,
                  nexus_fs_obj_type_t    type,
                  char                ** nexus_name)
{
    char * cmd_str   = NULL;
    char * path      = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;

    
    if (name[0] == '\\') {
	NEXUS_ERROR("Tried to remove strange file (%s)\n", name);
	ret = -1;
	goto out;
    }

    path = __get_path(avc);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for file (%s)\n", name);
	ret = -1;
	goto out;
    }
    
    cmd_str = kasprintf(GFP_KERNEL, generic_cmd_str, AFS_OP_REMOVE, name, path, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    RX_AFS_GLOCK();
    
    
    if (ret == -1) {
	NEXUS_ERROR("Error Sending Nexus Command\n");
	ret = -1;
	goto out;
    }

    // handle response...
    {
	struct nexus_json_param resp[2] = { {"code",       NEXUS_JSON_S32,    0},
					    {"nexus_name", NEXUS_JSON_STRING, 0} };

	s32 ret_code = 0;
	
	ret = nexus_json_parse(resp_data, resp, 2);
	
	if (ret != 0) {
	    NEXUS_ERROR("Could not parse JSON response\n");
	    ret = -1;
	    goto out;
	}

	ret_code = (s32)resp[0].val;
	
	if (ret_code != 0) {
	    NEXUS_ERROR("User space returned error... (%d)\n", ret_code);
	    ret = -1;
	    goto out;
	}

	*nexus_name = kstrdup((char *)resp[1].val, GFP_KERNEL);
    }

 out:
    if (path)      nexus_kfree(path);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);

    return ret;
}



/*

static const char * symlink_cmd_str =		\
    "{\n"					\
    "\"op\"   : %d,"     "\n"			\
    "\"source\" : \"%s\"," "\n"			\
    "\"target\" : \"%s\"," "\n"			\
    "}";

*/		    
int
nexus_kern_symlink(struct dentry  * dp,
		   char           * target,
		   char          ** dest)
{
    struct nx_daemon_rsp * reply     = NULL;
    caddr_t                global_outbuffer   = NULL;
    char                 * from_path = NULL;
    XDR                  * xdr_reply = NULL;
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

    if (    (xdr_string(&xdrs, &from_path, NEXUS_PATH_MAX)  == FALSE)
 	 || (xdr_string(&xdrs, &target,    NEXUS_FNAME_MAX) == FALSE)) {

        NEXUS_ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    if (nexus_mod_send(AFS_OP_SYMLINK, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;
    if (!xdr_string(xdr_reply, dest, NEXUS_FNAME_MAX)) {
        NEXUS_ERROR("parsing hardlink name failed\n");
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

        NEXUS_ERROR("xdr hardlink failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    if (nexus_mod_send(AFS_OP_HARDLINK, &xdrs, &reply, &code) || code) {
        goto out;
    }

    xdr_reply = &reply->xdrs;

    if (xdr_string(xdr_reply, dest, NEXUS_FNAME_MAX) == FALSE) {
        NEXUS_ERROR("parsing hardlink name failed\n");
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

        NEXUS_ERROR("xdr filldir failed\n");
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
        NEXUS_ERROR("parsing shadow_name failed\n");
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

        NEXUS_ERROR("xdr rename failed\n");
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

        NEXUS_ERROR("parsing rename response failed\n");
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

        NEXUS_ERROR("xdr storeacl failed\n");
        READPTR_UNLOCK();

        goto out;
    }

    if (nexus_mod_send(AFS_OP_STOREACL, &xdrs, &reply, &code) || code) {
        NEXUS_ERROR("xdr setacl (%s) FAILED\n", path);
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
