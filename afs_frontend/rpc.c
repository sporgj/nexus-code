#include <stdint.h>

#include <nexus.h>



#include "rpc.h"

#include "log.h"

int
rpc_ping(XDR * xdrs,
	 XDR * rsp)
{
    int magic = 0;

    if (!xdr_int(xdrs, &magic)) {
        log_error("Could not decode message");
        return -1;
    }

    log_debug("[ping] magic = %d", magic);

    return 0;
}

typedef int (*dirops_func_t)(const char *,
                             const char *,
                             nexus_fs_obj_type_t,
                             char **);

struct dirops_handler {
    afs_op_type_t   msg_type;
    char          * name;
    dirops_func_t   func;
};

struct dirops_handler dirops_map[] = {
    { AFS_OP_LOOKUP,  "lookup",  &dirops_lookup },
    { AFS_OP_FILLDIR, "filldir", &dirops_filldir  },
    { AFS_OP_REMOVE,  "remove",  &dirops_remove     },
    { AFS_OP_CREATE,  "create",  &dirops_new        },
    {0, 0, 0}
};

static struct dirops_handler *
get_dirops_handler(afs_op_type_t mtype)
{
    size_t i = 0;

    while (dirops_map[i].msg_type != 0) {

	if (dirops_map[i].msg_type == mtype) {
            return &dirops_map[i];
        }

	i++;
    }

    return NULL;
}

int
rpc_dirops(afs_op_type_t   msg_type,
	   XDR           * xdrs,
	   XDR           * xdr_out)
{
    struct dirops_handler * handler = get_dirops_handler(msg_type);

    char   * parent_dir = NULL;
    char   * name       = NULL;
    char   * shdw_name  = NULL;
    
    uint32_t type =  0;
    int      ret  = -1;

    
    if (handler == NULL) {
        log_error("invalid message type");
        return -1;
    }

    if ((xdr_string(xdrs, &parent_dir, NEXUS_PATH_MAX)  == FALSE) ||
	(xdr_string(xdrs, &name,       NEXUS_FNAME_MAX) == FALSE) ||
	(xdr_int(xdrs, (int *)&type)                    == FALSE) ) {

        log_error("error decoding message (type = %d)", msg_type);
        goto out;
    }

    if (handler->func(parent_dir, name, type, &shdw_name)) {
        /*log_error("[%s (%s)] %s/%s FAILED", tor->name, TYPE_TO_STR(msg_type),
                  parent_dir, name);*/
        goto out;
    }

    log_debug("[%s] %s/%s -> %s", handler->name, parent_dir, name, shdw_name);

    /* now start encoding the response */
    if (!xdr_string(xdr_out, &shdw_name, NEXUS_FNAME_MAX)) {
        log_error("ERROR encoding");
        goto out;
    }

    ret = 0;
out:
    if (parent_dir) {
        free(parent_dir);
    }

    if (name) {
        free(name);
    }

    if (shdw_name) {
        free(shdw_name);
    }

    return ret;
}

int
rpc_symlink(XDR * xdrs,
	    XDR * xdr_out)
{
    char * from_path   = NULL;
    char * target_link = NULL;
    char * shdw_name   = NULL;

    int ret = -1;

    // get the strings
    if ( (xdr_string(xdrs, &from_path,   NEXUS_PATH_MAX) == FALSE) ||
	 (xdr_string(xdrs, &target_link, NEXUS_PATH_MAX) == FALSE) ) {
        log_error("rpc_symlink decoding failed");
        goto out;
    }

    if (dirops_symlink(from_path, target_link, &shdw_name)) {
        log_error("[symlink] %s -> %s FAILED", from_path, target_link);
        goto out;
    }

    log_debug("[symlink] %s -> %s (%s)", from_path, target_link, shdw_name);

    if (!xdr_string(xdr_out, &shdw_name, NEXUS_FNAME_MAX)) {
        log_error("ERROR encoding symlink response");
        goto out;
    }

    ret = 0;
out:
    if (from_path) {
        free(from_path);
    }

    if (target_link) {
        free(target_link);
    }

    if (shdw_name) {
        free(shdw_name);
    }

    return ret;
}

int
rpc_hardlink(XDR * xdrs,
	     XDR * xdr_out)
{
    char * from_path = NULL;
    char * to_path   = NULL;
    char * shdw_name = NULL;

    int ret = -1;

    
    // get the strings
    if ((xdr_string(xdrs, &from_path, NEXUS_PATH_MAX) == FALSE) ||
        (xdr_string(xdrs, &to_path,   NEXUS_PATH_MAX) == FALSE) ) {
        log_error("rpc_hardlink decoding failed");
        goto out;
    }

    // FIXME clarify what from and to imply
    if (dirops_hardlink(from_path, to_path, &shdw_name)) {
        log_error("[hardlink] %s -> %s FAILED", from_path, to_path);
        goto out;
    }

    log_debug("[hardlink] %s -> %s (%s)", from_path, to_path, shdw_name);

    if (!xdr_string(xdr_out, &shdw_name, NEXUS_FNAME_MAX)) {
        log_error("ERROR encoding hardlink response");
        goto out;
    }

    ret = 0;
out:
    if (from_path) {
        free(from_path);
    }

    if (to_path) {
        free(to_path);
    }

    if (shdw_name) {
        free(shdw_name);
    }

    return ret;
}

int
rpc_rename(XDR * xdrs,
	   XDR * xdr_out)
{
    char * from_path      = NULL;
    char * to_path        = NULL;
    char * newname        = NULL;
    char * oldname        = NULL;
    char * old_shadowname = NULL;
    char * new_shadowname = NULL;

    int ret  = -1;


    if ( (xdr_string(xdrs, &from_path, NEXUS_PATH_MAX ) == FALSE) ||
	 (xdr_string(xdrs, &oldname,   NEXUS_FNAME_MAX) == FALSE) ||
	 (xdr_string(xdrs, &to_path,   NEXUS_PATH_MAX ) == FALSE) ||
	 (xdr_string(xdrs, &newname,   NEXUS_FNAME_MAX) == FALSE) ) {
        log_error("xdr rename failed");
        goto out;
    }

    ret = dirops_move(from_path,
		      oldname,
		      to_path,
		      newname,
                      &old_shadowname,
		      &new_shadowname);
    if (ret) {
        log_error("[rename] %s/%s -> %s/%s FAILED", from_path, oldname, to_path,
                  newname);
        goto out;
    }

    log_debug("[rename] %s/%s -> %s/%s", from_path, oldname, to_path, newname);

    if ( (xdr_string(xdr_out, &old_shadowname, NEXUS_FNAME_MAX) == FALSE) ||
	 (xdr_string(xdr_out, &new_shadowname, NEXUS_FNAME_MAX) == FALSE) ) {
        log_error("encoding rename response failed");
        goto out;
    }

    ret = 0;
out:
    if (from_path) {
        free(from_path);
    }

    if (newname) {
        free(newname);
    }

    if (to_path) {
        free(to_path);
    }

    if (oldname) {
        free(oldname);
    }

    if (old_shadowname) {
        free(old_shadowname);
    }

    if (new_shadowname) {
        free(new_shadowname);
    }

    return ret;
}

int
rpc_storeacl(XDR * xdrs,
	     XDR * xdr_out)
{
    caddr_t   acl_data = NULL;
    char    * path     = NULL;

    int ret = -1;
    int len =  0;

    if ( (xdr_string(xdrs, &path, NEXUS_PATH_MAX) == FALSE) ||
	 (xdr_int(xdrs, &len)                     == FALSE) ) {
        log_error("xdr storeacl failed\n");
        goto out;
    }

    acl_data = (caddr_t)malloc(len);
	
    if (acl_data == NULL) {
        goto out;
    }

    if (!xdr_opaque(xdrs, acl_data, len)) {
        log_error("xdr acl_data failed\n");
        goto out;
    }

    if (dirops_setacl(path, acl_data)) {
        log_error("dirops_setacl failed\n");
        goto out;
    }

    log_debug("[storeacl] %s", path);

    ret = 0;
out:
    if (path) {
        free(path);
    }

    if (acl_data) {
        free(acl_data);
    }

    return ret;
}

int
rpc_xfer_init(XDR * xdrs,
	      XDR * xdr_out)
{
    xfer_req_t   xfer_req;
    xfer_rsp_t   xfer_rsp;
    char       * fpath  = NULL;
    
    int ret     = -1;
   
    /* get the data from the wire */
    if ((xdr_opaque(xdrs, (caddr_t)&xfer_req, sizeof(xfer_req_t)) == FALSE) ||
	(xdr_string(xdrs, &fpath, NEXUS_PATH_MAX)                 == FALSE) ) {
        log_error("xdr parsing for store start failed");
        goto out;
    }

    printf("XFER INIT Was Called\n");

    
    // otherwise, lets just setup our response
    if (xdr_opaque(xdr_out, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t)) == FALSE) {
        log_error("Error with setting xfer_rsp");
        goto out;
    }

#if 0
    log_debug("[%s] id=%d (xfer_size=%d, file_size=%d, offset=%d) %s",
	      (xfer_req.op == NEXUS_STORE) ? "nexus_store" : "nexus_fetch",
	      xfer_rsp.xfer_id,
	      xfer_req.xfer_size,
	      xfer_req.file_size,
	      xfer_req.offset,
	      fpath);
#endif

    ret = 0;
out:
    if (fpath) {
        free(fpath);
    }

    return ret;
}

int
rpc_xfer_run(XDR * xdrs,
	     XDR * xdr_out)
{
    int ret      = -1;
    int xfer_id  =  0;
    int xfer_len =  0;

    /* get params and call fetchstore to do some encryption */
    if ((xdr_int(xdrs, &xfer_id)  == FALSE) ||
	(xdr_int(xdrs, &xfer_len) == FALSE) ) {
        log_error("xdr parsing of transfer run failed");
        goto out;
    }

    printf("XFER RUN WAS CALLED\n");
    
    ret = 0;
out:
    return ret;
}

int
rpc_xfer_exit(XDR * xdrs,
	      XDR * xdr_out)
{
    int ret      = -1;
    int xfer_id  =  0;

    /* get params and call fetchstore to do some encryption */
    if (xdr_int(xdrs, &xfer_id) == FALSE) {
        log_error("xdr parsing of xfer_exit failed");
        goto out;
    }

    printf("FETCHSTORE EXIT WAS CALLED\n");
    
    ret = 0;
out:
    return ret;
}
