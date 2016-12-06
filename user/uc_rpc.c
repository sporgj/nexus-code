#include "afsx.h"
#include "cdefs.h"
#include "uc_dirops.h"
#include "uc_fetchstore.h"
#include "uc_fileops.h"
#include "uc_utils.h"

#define N_SECURITY_OBJECTS 1
bool_t
xdr_ucafs_entry_type(XDR * xdrs, ucafs_entry_type * lp)
{
    // TODO no need to make the additional call_
    return xdr_afs_uint32(xdrs, (afs_uint32 *)lp);
}

int
setup_rx(int port)
{
    struct rx_securityClass *(security_objs[N_SECURITY_OBJECTS]);
    struct rx_service * service;
    int ret = 1;

    port = (port == 0) ? AFSX_SERVER_PORT : port;

    if (rx_Init(port) < 0) {
        uerror("rx_init");
        goto out;
    }

    // create the null security object, UNAUTHENTICATED access
    security_objs[AFSX_NULL] = rxnull_NewServerSecurityObject();
    if (security_objs[AFSX_NULL] == NULL) {
        uerror("rxnull_NewServerSecurityObject");
        goto out;
    }

    // instantiate our service
    service = rx_NewService(0, AFSX_SERVICE_ID, (char *)"afsx", security_objs,
                            N_SECURITY_OBJECTS, AFSX_ExecuteRequest);
    if (service == NULL) {
        uerror("rx_NewService");
        goto out;
    }

    uinfo("Waiting for connections [0:%d]...", port);
    rx_StartServer(1);
    /* Note that the above call forks into another process */

    uerror("StartServer returned: ");

    ret = 0;
out:
    return ret;
}

afs_int32
SAFSX_fversion(
    /*IN */ struct rx_call * z_call,
    /*IN */ int dummy,
    /*OOU */ int * result)
{
    *result = 1;
    printf("PING from kernel\n");

    return 0;
}

static const char *
struct_type_to_str(ucafs_entry_type type)
{
    switch (type) {
    case UC_FILE:
        return "touch";
    case UC_DIR:
        return "mkdir";
    case UC_LINK:
        return "softlink";
    default:
        return "(unknown)";
    }
}

afs_int32
SAFSX_create(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * path,
    /*IN */ afs_int32 type,
    /*OUT*/ char ** crypto_fname)
{
    int ret = dirops_new(path, type, crypto_fname);
    if (ret) {
        *crypto_fname = EMPTY_STR_HEAP;
    } else {
        uinfo("%s: %s ~> %s", struct_type_to_str(type), path, *crypto_fname);
    }
    return ret;
}

afs_int32 SAFSX_create1(
	/*IN */ struct rx_call *z_call,
	/*IN */ char * parent_dir,
	/*IN */ char * name,
	/*IN */ afs_int32 type,
	/*OUT*/ char * *shadow_name_dest)
{
    int ret = dirops_new1(parent_dir, name, type, shadow_name_dest);
    if (ret) {
        *shadow_name_dest = EMPTY_STR_HEAP;
    } else {
        uinfo("%s: %s/%s ~> %s", struct_type_to_str(type), parent_dir, name,
              *shadow_name_dest);
    }
    return ret;
}

afs_int32
SAFSX_find(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fake_name,
    /*IN */ char * path,
    /*IN */ afs_int32 type,
    /*OUT*/ char ** real_name)
{
    int ret = dirops_code2plain(fake_name, path, type, real_name);
    if (ret) {
        *real_name = EMPTY_STR_HEAP;
    } else {
        uinfo("> decode: %s ~> %s", fake_name, *real_name);
    }
    return ret;
}

afs_int32
SAFSX_lookup(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_int32 type,
    /*OUT*/ char ** fake_name)
{
    int ret = dirops_plain2code(fpath, type, fake_name);
    if (ret) {
        *fake_name = EMPTY_STR_HEAP;
    } else {
        uinfo("fencode: %s ~> %s", fpath, *fake_name);
    }
    return ret;
}

afs_int32
SAFSX_rename(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * from_path,
    /*IN */ char * oldname,
    /*IN */ char * to_path,
    /*IN */ char * newname,
    /*IN */ afs_int32 type,
    /*OUT*/ char ** old_shadow_name,
    /*OUT*/ char ** new_shadow_name)
{
    int ret = dirops_move(from_path, oldname, to_path, newname, type,
                          old_shadow_name, new_shadow_name);
    if (ret) {
        *old_shadow_name = EMPTY_STR_HEAP;
        *new_shadow_name = EMPTY_STR_HEAP;
    } else {
        uinfo("Renamed '%s' -> '%s'", oldname, newname);
    }

    return ret;
}

afs_int32
SAFSX_remove(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_int32 type,
    /*OUT*/ char ** code_name)
{
    const char * str = (type == UC_DIR) ? "rmdir" : "rm";
    int ret = dirops_remove(fpath, type, code_name);
    if (ret) {
        *code_name = EMPTY_STR_HEAP;
    } else {
        uinfo("%s: %s ~> %s", str, fpath, *code_name);
    }
    return ret;
}

afs_int32
SAFSX_hardlink(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * old_path,
    /*IN */ char * new_path,
    /*OUT*/ char ** code_name)
{
    int ret = dirops_hardlink(old_path, new_path, code_name);
    if (ret) {
        *code_name = EMPTY_STR_HEAP;
    } else {
        uinfo("hardlink: %s (%s) ~> %s", new_path, *code_name, old_path);
    }
    return ret;
}

afs_int32 SAFSX_symlink(
	/*IN */ struct rx_call *z_call,
	/*IN */ char * old_path,
	/*IN */ char * new_path,
	/*OUT*/ char * *code_name)
{
    int ret = dirops_symlink(old_path, new_path, code_name);
    if (ret) {
        *code_name = EMPTY_STR_HEAP;
    } else {
        uinfo("symlink: %s (%s) ~> %s", new_path, *code_name, old_path);
    }
    return ret;
}

#define RWOP_TO_STR(op) (op == UC_ENCRYPT ? "write" : "read")
afs_int32
SAFSX_readwrite_start(
    /*IN */ struct rx_call * z_call,
    /*IN */ int op,
    /*IN */ char * fpath,
    /*IN */ afs_uint32 max_chunk_size,
    /*IN */ afs_uint32 offset,
    /*IN */ afs_uint32 total_size,
    /*OUT*/ afs_int32 * id)
{
    int ret;
    xfer_context_t * ctx;

    ret = fileops_start(op, fpath, max_chunk_size, offset, total_size, id);
    if (ctx == NULL) {
        if (ret == -2) {
            uerror("rw: %s, enclave failed", fpath);
            return AFSX_STATUS_ERROR;
        }
        return AFSX_STATUS_NOOP;
    }

    uinfo("begin %s: %s (%u, %u, %u) id=%d", RWOP_TO_STR(op), fpath,
          max_chunk_size, offset, total_size, *id);

    return AFSX_STATUS_SUCCESS;
}

afs_int32
SAFSX_readwrite_finish(
    /*IN */ struct rx_call * z_call,
    /*IN */ afs_int32 id)
{
    return fileops_finish(id);
}

afs_int32
SAFSX_readwrite_data(
    /*IN */ struct rx_call * z_call,
    /*IN */ afs_int32 id,
    /*IN */ afs_uint32 size,
    /*OUT */ int * moredata)
{
    int ret = AFSX_STATUS_ERROR;
    afs_uint32 abytes;

    uint8_t ** buf = fileops_get_buffer(id, size);
    if (buf == NULL) {
        goto out;
    }

    if ((abytes = rx_Read(z_call, *buf, size)) != size) {
        uerror("Read error. expecting: %u, actual: %u (err = %d)", size, abytes,
               rx_Error(z_call));
        goto out;
    }

    // TODO check return
    fileops_process_data(buf);

    if ((abytes = rx_Write(z_call, *buf, size)) != size) {
        uerror("Write error. Expecting: %u, Actual: %u (err = %d)", size,
               abytes, rx_Error(z_call));
        goto out;
    }

    ret = 0;
out:
    return ret;
}

afs_int32 SAFSX_fetchstore_start(
	/*IN */ struct rx_call *z_call,
	/*IN */ int op,
	/*IN */ char * fpath,
	/*IN */ afs_uint32 max_xfer_size,
	/*IN */ afs_uint32 file_offset,
	/*IN */ afs_uint32 file_size,
	/*OUT*/ afs_int32 * xfer_id,
    /*OUT*/ afs_uint32 * fbox_len,
	/*OUT*/ afs_uint32 * total_len)
{
    int ret = fetchstore_start(op, fpath, max_xfer_size, file_offset, file_size,
                               xfer_id, fbox_len, total_len);
    if (ret == 0) {
        uinfo("%s (id = %d): %s (%u, %u, %u)", RWOP_TO_STR(op), *xfer_id, fpath,
                file_offset, max_xfer_size, file_size);
    }

    return ret;
}

afs_int32 SAFSX_fetchstore_finish(
        /*IN */ struct rx_call * z_call,
        /*IN */ afs_int32 id)
{
    return fetchstore_finish(id);
}

afs_int32
SAFSX_fetchstore_data(
    /*IN */ struct rx_call * z_call,
    /*IN */ afs_int32 id,
    /*IN */ afs_uint32 size)
{
    int ret = AFSX_STATUS_ERROR, op;
    afs_uint32 abytes;

    uint8_t ** buf = fetchstore_get_buffer(id, size, &op);
    if (buf == NULL) {
        goto out;
    }

    if ((abytes = rx_Read(z_call, *buf, size)) != size) {
        uerror("Read error. expecting: %u, actual: %u (err = %d)", size, abytes,
               rx_Error(z_call));
        goto out;
    }

    if (fetchstore_process_data(buf)) {
        uerror("(id = %d) error processing data :( terminating everything", id);
        goto out;
    }

    if ((abytes = rx_Write(z_call, *buf, size)) != size) {
        uerror("Write error. Expecting: %u, Actual: %u (err = %d)", size,
               abytes, rx_Error(z_call));
        goto out;
    }

    ret = 0;
out:
    return ret;
}

afs_int32 SAFSX_fetchstore_fbox(
	/*IN */ struct rx_call *z_call,
	/*IN */ afs_int32 id,
    /*IN */ afs_int32 fbox_op,
	/*IN */ afs_uint32 size)
{
    int ret = AFSX_STATUS_ERROR, op;
    afs_uint32 abytes;

    uint8_t ** buf = fetchstore_get_buffer(id, size, &op);
    if (buf == NULL) {
        goto out;
    }

    if (fbox_op == UCAFS_FBOX_WRITE) {
        if ((abytes = rx_Read(z_call, *buf, size)) != size) {
            uerror("Write error. Expecting: %u, Actual: %u (err = %d)", size,
                    abytes, rx_Error(z_call));
            goto out;
        }
    }

    if (fetchstore_process_fbox(buf)) {
        uerror("(id = %d) error processing data :( terminating everything", id);
        goto out;
    }

    if (fbox_op == UCAFS_FBOX_READ) {
        if ((abytes = rx_Write(z_call, *buf, size)) != size) {
            uerror("Read error. expecting: %u, actual: %u (err = %d)", size, abytes,
                   rx_Error(z_call));
            goto out;
        }
    }

    ret = 0;
out:
    return ret;
}
