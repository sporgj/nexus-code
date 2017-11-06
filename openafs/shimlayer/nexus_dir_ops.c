#include <linux/kernel.h>
#include <linux/limits.h>

#include "nexus_module.h"
#include "nexus_json.h"
#include "nexus_util.h"
#include "nexus_kern.h"
#include "nexus_volume.h"


/* from <linux/limits.h>
 * PATH_MAX ==> Maximum Path Length 
 * NAME_MAX ==> Maximum File Name Length 
 */





static const char * generic_cmd_str =		\
    "\"op\"   : %d,"     "\n"			\
    "\"name\" : \"%s\"," "\n"			\
    "\"path\" : \"%s\"," "\n"			\
    "\"type\" : %d"      "\n";


int
nexus_kern_create(struct vcache        * avc,
		  char                 * name,
		  nexus_fs_obj_type_t    type,
		  char                ** nexus_name)
{
    struct nexus_volume * vol = NULL;
    
    char * cmd_str   = NULL;
    char * path      = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;

    
    if (name[0] == '\\') {
	NEXUS_ERROR("Tried to create strange file (%s)\n", name);
	ret = -1;
	goto out;
    }

    path = nexus_get_path_from_vcache(avc);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for new file (%s)\n", name);
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Nexus Create (Path=%s)\n", path); 

    vol = nexus_get_volume(path);

    if (vol == NULL) {
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Found Nexus Volume (%s)\n", vol->path);
    
    cmd_str = kasprintf(GFP_KERNEL, generic_cmd_str, AFS_OP_CREATE, name, path, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }


    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
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
    if (vol)       nexus_put_volume(vol);
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
    struct nexus_volume * vol = NULL;
    
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

    path = nexus_get_path_from_vcache(avc);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for file (%s)\n", name);
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Nexus Lookup (Path=%s)\n", path); 

    vol = nexus_get_volume(path);

    if (vol == NULL) {
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Found Nexus Volume (%s)\n", vol->path);
    
    cmd_str = kasprintf(GFP_KERNEL, generic_cmd_str, AFS_OP_LOOKUP, name, path, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
    
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
    if (vol)       nexus_put_volume(vol);
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
    struct nexus_volume * vol = NULL;
    
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

    path = nexus_get_path_from_vcache(avc);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for file (%s)\n", name);
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Nexus Remove (Path=%s)\n", path); 

    vol = nexus_get_volume(path);

    if (vol == NULL) {
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Found Nexus Volume (%s)\n", vol->path);
    
    cmd_str = kasprintf(GFP_KERNEL, generic_cmd_str, AFS_OP_REMOVE, name, path, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
    
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
    if (vol)       nexus_put_volume(vol);
    if (path)      nexus_kfree(path);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);

    return ret;
}




static const char * symlink_cmd_str =		\
    "\"op\"     : %d,"     "\n"			\
    "\"source\" : \"%s\"," "\n"			\
    "\"target\" : \"%s\"" "\n";


int
nexus_kern_symlink(struct dentry  * dentry,
		   char           * target,
		   char          ** nexus_name)
{
    struct nexus_volume * vol = NULL;

    char * cmd_str   = NULL;
    char * path      = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;
    
    path = nexus_get_path_from_dentry(dentry);

      if (path == NULL) {
	NEXUS_ERROR("Could not get path for dentry\n");
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Nexus Symlink (Path=%s)\n", path); 

    vol = nexus_get_volume(path);

    if (vol == NULL) {
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Found Nexus Volume (%s)\n", vol->path);

    cmd_str = kasprintf(GFP_KERNEL, symlink_cmd_str, AFS_OP_SYMLINK, path, target);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
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
    if (vol)       nexus_put_volume(vol);
    if (path)      nexus_kfree(path);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);

    return ret;
}


static const char * hardlink_cmd_str =		\
    "\"op\"     : %d,"     "\n"			\
    "\"source\" : \"%s\"," "\n"			\
    "\"target\" : \"%s\"," "\n";

int
nexus_kern_hardlink(struct dentry  * old_dentry,
		    struct dentry  * new_dentry,
		    char          ** nexus_name)
{
    struct nexus_volume * vol     = NULL;
    struct nexus_volume * tgt_vol = NULL;
    
    char * cmd_str   = NULL;
    char * path      = NULL;
    char * target    = NULL;
    
    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;
    
    path = nexus_get_path_from_dentry(old_dentry);
    
    if (path == NULL) {
	NEXUS_ERROR("Could not get path for dentry\n");
	ret = -1;
	goto out;
    }

    target = nexus_get_path_from_dentry(new_dentry);

    if (path == NULL) {
	NEXUS_ERROR("Could not get path for dentry\n");
	ret = -1;
	goto out;
    }
    

    NEXUS_DEBUG("Nexus Hardlink (Path=%s)\n", path); 

    vol = nexus_get_volume(path);

    if (vol == NULL) {
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Found Nexus Volume (%s)\n", vol->path);

    tgt_vol = nexus_get_volume(target);

    if (tgt_vol != vol) {
	NEXUS_ERROR("Source and Target of hardlink are not in the same volume\n");
	ret = -1;
	goto out;
    }
    
    cmd_str = kasprintf(GFP_KERNEL, hardlink_cmd_str, AFS_OP_HARDLINK, path, target);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
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
    if (vol)       nexus_put_volume(vol);
    if (tgt_vol)   nexus_put_volume(tgt_vol);
    if (path)      nexus_kfree(path);
    if (target)    nexus_kfree(target);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);

    return ret;
}

static const char * filldir_cmd_str =			\
    "\"op\"         : %d,"     "\n"			\
    "\"path\"       : \"%s\"," "\n"			\
    "\"nexus_name\" : \"%s\"," "\n"			\
    "\"type\"       : %d"      "\n";

int
nexus_kern_filldir(char                 * parent_dir,
                   char                 * nexus_name,
                   nexus_fs_obj_type_t    type,
                   char                ** real_name)
{
    struct nexus_volume * vol = NULL;
    
    char * cmd_str   = NULL;
    
    char * resp_data = NULL;
    u32    resp_len  = 0;

    int    ret       = 0;

    vol = nexus_get_volume(parent_dir);

    if (vol == NULL) {
	ret = -1;
	goto out;
    }

    
    cmd_str = kasprintf(GFP_KERNEL, filldir_cmd_str, AFS_OP_FILLDIR, parent_dir, nexus_name, type);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    ret = nexus_send_cmd(vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
    
    if (ret == -1) {
	NEXUS_ERROR("Error Sending Nexus Command\n");
	ret = -1;
	goto out;
    }

    // handle response...
    {
	struct nexus_json_param resp[2] = { {"code",      NEXUS_JSON_S32,    0},
					    {"real_name", NEXUS_JSON_STRING, 0} };

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

	*real_name = kstrdup((char *)resp[1].val, GFP_KERNEL);

	nexus_json_release_params(resp, 2);
    }

    
 out:
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);

    return ret;
}

static const char * rename_cmd_str =		\
    "\"op\"        : %d,"     "\n"		\
    "\"old_path\"  : \"%s\"," "\n"		\
    "\"old_name\"  : \"%s\"," "\n"		\
    "\"new_path\"  : \"%s\"," "\n"		\
    "\"new_name\"  : \"%s\""  "\n";


int
nexus_kern_rename(struct vcache  * old_vcache,
                  char           * old_name,
                  struct vcache  * new_vcache,
                  char           * new_name,
                  char          ** old_nexus_name,
                  char          ** new_nexus_name)
{

    struct nexus_volume * old_vol      = NULL;
    struct nexus_volume * new_vol      = NULL;

    struct mutex        * rename_mutex = NULL;

    char * old_path  = NULL;
    char * new_path  = NULL;
    char * cmd_str   = NULL;

    char * resp_data = NULL;
    u32    resp_len  = 0;

    
    int unlocked = 0;
    
    int ret = 0;

    
    old_path = nexus_get_path_from_vcache(old_vcache);

    if (old_path == NULL) {
	NEXUS_ERROR("Could not get path for old file (%s)\n", old_name);
	ret = -1;
	goto out;
    }

    new_path = nexus_get_path_from_vcache(new_vcache);

    if (new_path == NULL) {
	NEXUS_ERROR("Could not get path for old file (%s)\n", new_name);
	ret = -1;
	goto out;
    }
    
    nexus_printk("Renaming %s/%s to %s/%s\n",
		 old_path, old_name,
		 new_path, new_name);

    old_vol = nexus_get_volume(old_path);
    new_vol = nexus_get_volume(new_path);

    /* 
     * TODO: I think this should work if we are crossing Nexus boundaries......
     *       I think we should change the command to a single path translation
     *       and issue two (one for each side of the operation)
     */
    
    if ( (old_vol == NULL) &&
	 (new_vol == NULL) ) {
	/* No volumes at all */
	ret = -1;
	goto out;
    }

    NEXUS_DEBUG("Found Nexus Volumes (old_vol=%s) (new_vol=%s)\n", old_vol->path, new_vol->path);

    
    if (old_vol != new_vol) {
	NEXUS_ERROR("Rename spans Nexus volume boundaries\n");
	panic("What the fuck do we do here....\n");
	ret = -1;
	goto out;
    }
    
    cmd_str = kasprintf(GFP_KERNEL, rename_cmd_str, AFS_OP_RENAME, old_path, old_name, new_path, new_name);

    if (cmd_str == NULL) {
	NEXUS_ERROR("Could not create command string\n");
	ret = -1;
	goto out;
    }

    AFS_GUNLOCK();
    
    /* check if cross directory renaming is present */
    rename_mutex = &AFSTOV(old_vcache)->i_sb->s_vfs_rename_mutex;

    if (mutex_is_locked(rename_mutex)) {
        mutex_unlock(rename_mutex);
        unlocked = 1;
    }
    
    ret = nexus_send_cmd(old_vol, strlen(cmd_str) + 1, cmd_str, &resp_len, (u8 **)&resp_data);
    AFS_GLOCK();
    
    if (ret == -1) {
	NEXUS_ERROR("Error Sending Nexus Command\n");
	ret = -1;
	goto out;
    }
    

    // handle response...
    {
	struct nexus_json_param resp[3] = { {"code",           NEXUS_JSON_S32,    0},
					    {"old_nexus_name", NEXUS_JSON_STRING, 0},
					    {"new_nexus_name", NEXUS_JSON_STRING, 0} };

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

	*old_nexus_name = kstrdup((char *)resp[1].val, GFP_KERNEL);
	*new_nexus_name = kstrdup((char *)resp[2].val, GFP_KERNEL);
    }


 out:
    if (unlocked)  mutex_lock(rename_mutex);
    if (old_vol)   nexus_put_volume(old_vol);
    if (new_vol)   nexus_put_volume(new_vol);
    if (old_path)  nexus_kfree(old_path);
    if (new_path)  nexus_kfree(new_path);
    if (cmd_str)   nexus_kfree(cmd_str);
    if (resp_data) nexus_kfree(resp_data);
    
    return ret;
}

int
nexus_kern_storeacl(struct vcache * avc, AFSOpaque * acl_data)
{

#if 0
    
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
#endif
    return -1;

}
