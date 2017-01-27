#include "uc_rpc.h"
#include "uc_dirops.h"
#include "uc_fetchstore.h"
#include "uc_types.h"

#include "cdefs.h"
#include "third/log.h"

int
uc_rpc_ping(XDR * xdrs, XDR * rsp)
{
    int l;

    if (!xdr_int(xdrs, &l)) {
        uerror("Could not decode message");
        return -1;
    }

    log_info("[ping] magic = %d", l);

    return 0;
}

typedef int (*dirops_func_t)(const char *,
                             const char *,
                             ucafs_entry_type,
                             char **);

typedef struct {
    uc_msg_type_t msg_type;
    char * name;
    dirops_func_t func;
} dirops_str_and_func_t;

dirops_str_and_func_t dirops_map[]
    = { { UCAFS_MSG_LOOKUP, "lookup", &dirops_plain2code1 },
        { UCAFS_MSG_FILLDIR, "filldir", &dirops_code2plain },
        { UCAFS_MSG_REMOVE, "remove", &dirops_remove1 },
        { UCAFS_MSG_CREATE, "create", &dirops_new1 } };

static inline dirops_str_and_func_t *
msg_func_and_string(uc_msg_type_t mtype)
{
    size_t i = 0;
    for (; i < sizeof(dirops_map) / sizeof(dirops_str_and_func_t); i++) {
        if (dirops_map[i].msg_type == mtype) {
            return &dirops_map[i];
        }
    }

    return NULL;
}

int
uc_rpc_dirops(uc_msg_type_t msg_type, XDR * xdrs, XDR * xdr_out)
{
    int ret;
    afs_int32 type;
    char *parent_dir = NULL, *name = NULL, *shdw_name = NULL;
    dirops_str_and_func_t * tor = msg_func_and_string(msg_type);
    if (tor == NULL) {
        uerror("invalid message type");
        return -1;
    }

    if (!xdr_string(xdrs, &parent_dir, UCAFS_PATH_MAX)
        || !xdr_string(xdrs, &name, UCAFS_FNAME_MAX)
        || !xdr_int(xdrs, (int *)&type)) {
        uerror("%s error decoding message", TYPE_TO_STR(msg_type));
        goto out;
    }

    if (tor->func(parent_dir, name, type, &shdw_name)) {
        log_error("[%s (%s)] %s/%s FAILED", tor->name, TYPE_TO_STR(msg_type),
                  parent_dir, name);
        goto out;
    }

    log_info("[%s (%s)] %s/%s -> %s", tor->name, TYPE_TO_STR(type), parent_dir,
             name, shdw_name);

    /* now start encoding the response */
    if (!xdr_string(xdr_out, &shdw_name, UCAFS_FNAME_MAX)) {
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
uc_rpc_symlink(XDR * xdrs, XDR * xdr_out)
{
    int ret;
    char *from_path = NULL, *target_link = NULL, *shdw_name = NULL;

    // get the strings
    if (!xdr_string(xdrs, &from_path, UCAFS_PATH_MAX)
        || !xdr_string(xdrs, &target_link, UCAFS_PATH_MAX)) {
        uerror("uc_rpc_symlink decoding failed");
        goto out;
    }

    if (dirops_symlink(from_path, target_link, &shdw_name)) {
        log_error("[symlink] %s -> %s FAILED", from_path, target_link);
        goto out;
    }

    log_info("[symlink] %s -> %s (%s)", from_path, target_link, shdw_name);

    if (!xdr_string(xdr_out, &shdw_name, UCAFS_FNAME_MAX)) {
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
uc_rpc_hardlink(XDR * xdrs, XDR * xdr_out)
{
    int ret;
    char *from_path = NULL, *to_path = NULL, *shdw_name = NULL;

    // get the strings
    if (!xdr_string(xdrs, &from_path, UCAFS_PATH_MAX)
        || !xdr_string(xdrs, &to_path, UCAFS_PATH_MAX)) {
        uerror("uc_rpc_hardlink decoding failed");
        goto out;
    }

    // FIXME clarify what from and to imply
    if (dirops_hardlink(from_path, to_path, &shdw_name)) {
        log_error("[hardlink] %s -> %s FAILED", from_path, to_path);
        goto out;
    }

    log_info("[hardlink] %s -> %s (%s)", from_path, to_path, shdw_name);

    if (!xdr_string(xdr_out, &shdw_name, UCAFS_FNAME_MAX)) {
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
uc_rpc_rename(XDR * xdrs, XDR * xdr_out)
{
    int ret = -1, code;
    char *from_path = NULL, *to_path = NULL, *newname = NULL, *oldname = NULL,
         *old_shadowname = NULL, *new_shadowname = NULL;

    if (!xdr_string(xdrs, &from_path, UCAFS_PATH_MAX)
        || !xdr_string(xdrs, &oldname, UCAFS_FNAME_MAX)
        || !xdr_string(xdrs, &to_path, UCAFS_PATH_MAX)
        || !xdr_string(xdrs, &newname, UCAFS_FNAME_MAX)) {
        uerror("xdr rename failed");
        goto out;
    }

    ret = dirops_move(from_path, oldname, to_path, newname, UC_ANY,
                      &old_shadowname, &new_shadowname);
    if (ret) {
        log_error("[rename] %s/%s -> %s/%s FAILED", from_path, oldname, to_path,
                  newname);
        goto out;
    }

    log_info("[rename] %s/%s -> %s/%s", from_path, oldname, to_path, newname);

    if (!xdr_string(xdr_out, &old_shadowname, UCAFS_FNAME_MAX)
        || !xdr_string(xdr_out, &new_shadowname, UCAFS_FNAME_MAX)) {
        uerror("encoding rename response failed");
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
uc_rpc_xfer_init(XDR * xdrs, XDR * xdr_out)
{
    int ret = -1, xfer_id, dummy;
    size_t nbytes;
    xfer_req_t xfer_req;
    xfer_rsp_t xfer_rsp;
    char * fpath = NULL;

    /* get the data from the wire */
    if (!xdr_opaque(xdrs, (caddr_t)&xfer_req, sizeof(xfer_req_t))
        || !xdr_string(xdrs, &fpath, UCAFS_PATH_MAX)) {
        uerror("xdr parsing for store start failed");
        goto out;
    }

    // call fetchstore start
    if (fetchstore_init(&xfer_req, fpath, &xfer_rsp)) {
        log_error("fetchstore_start failed :(");
        goto out;
    }

    // otherwise, lets just setup our response
    if (!xdr_opaque(xdr_out, (caddr_t)&xfer_rsp, sizeof(xfer_rsp_t))) {
        log_error("Error with setting xfer_rsp");
        goto out;
    }

    log_info("[%s] id=%d (xfer_size=%d, file_size=%d, offset=%d) %s",
             (xfer_req.op == UCAFS_STORE ? "ucafs_store" : "ucafs_fetch"),
             xfer_rsp.xfer_id, xfer_req.xfer_size, xfer_req.file_size,
             xfer_req.offset, fpath);

    ret = 0;
out:
    if (fpath) {
        free(fpath);
    }

    return ret;
}

int
uc_rpc_xfer_run(XDR * xdrs, XDR * xdr_out)
{
    int ret = -1, xfer_id, xfer_len;

    /* get params and call fetchstore to do some encryption */
    if (!xdr_int(xdrs, &xfer_id) || !xdr_int(xdrs, &xfer_len)) {
        uerror("xdr parsing of transfer run failed");
        goto out;
    }

    if ((ret = fetchstore_run(xfer_id, xfer_len))) {
        log_error("fetchstore_run faild ret=%d", ret);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

int
uc_rpc_xfer_exit(XDR * xdrs, XDR * xdr_out)
{
    int ret = -1, xfer_id, xfer_len;

    /* get params and call fetchstore to do some encryption */
    if (!xdr_int(xdrs, &xfer_id)) {
        uerror("xdr parsing of xfer_exit failed");
        goto out;
    }

    if ((ret = fetchstore_finish(xfer_id))) {
        log_error("fetchstore_finish faild ret=%d", ret);
        goto out;
    }

    ret = 0;
out:
    return ret;
}
