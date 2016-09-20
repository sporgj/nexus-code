#include "cdefs.h"
#include "afsx.h"
#include "dirops.h"
#include "fileops.h"
#include "afsx_hdr.h"
#include "utils.h"

#define N_SECURITY_OBJECTS 1

int setup_rx(int port)
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

afs_int32 SAFSX_fversion(
    /*IN */ struct rx_call * z_call,
    /*IN */ int dummy,
    /*OOU */ int * result)
{
    *result = 1;
    printf("PING from kernel\n");

    return 0;
}

afs_int32 SAFSX_create(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * path,
    /*IN */ afs_int32 file_or_dir,
    /*OUT*/ char ** crypto_fname)
{
    int ret = (file_or_dir == AFSX_IS_FILE) ? fops_new(path, crypto_fname)
                                            : dops_new(path, crypto_fname);
    if (ret) {
        *crypto_fname = EMPTY_STR_HEAP;
        uerror("create FAILED (ret=%d): %s", ret, path);
    } else {
        uinfo("%s: %s ~> %s", (file_or_dir == AFSX_IS_FILE ? "touch" : "mkdir"),
              path, *crypto_fname);
    }
    return ret;
}

afs_int32 SAFSX_frealname(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fake_name,
    /*IN */ char * path,
    /*OUT*/ char ** plain_name)
{
    int ret = fops_code2plain(fake_name, path, plain_name);
    if (ret) {
        *plain_name = EMPTY_STR_HEAP;
    } else {
        uinfo("> decode: %s ~> %s", fake_name, *plain_name);
    }
    return ret;
}

afs_int32 SAFSX_fencodename(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*OUT*/ char ** code_name_str)
{
    int ret = fops_plain2code(fpath, code_name_str);
    if (ret) {
        *code_name_str = EMPTY_STR_HEAP;
    } else {
        printf("fencode: %s ~> %s\n", fpath, *code_name_str);
    }
    return ret;
}

afs_int32 SAFSX_rename(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * old_fpath,
    /*IN */ char * new_path,
    /*IN */ afs_int32 file_or_dir,
    /*OUT*/ char ** code_name)
{
    int ret = dirops_rename(old_fpath, new_path, file_or_dir, code_name);
    if (ret) {
        *code_name = EMPTY_STR_HEAP;
        uerror("Renaming '%s' -> '%s' FAILED", old_fpath, new_path);
    } else {
        uinfo("Renamed '%s' -> '%s'", old_fpath, new_path);
    }

    return ret;
}

afs_int32 SAFSX_remove(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_int32 file_or_dir,
    /*OUT*/ char ** code_name)
{
    const char * str = file_or_dir == AFSX_IS_FILE ? "rm" : "rmdir";
    int ret = file_or_dir == AFSX_IS_FILE ? fops_remove(fpath, code_name)
                                          : dops_remove(fpath, code_name);
    if (ret) {
        *code_name = EMPTY_STR_HEAP;
        uerror("%s FAILED: %s", str, fpath);
    } else {
        uinfo("%s: %s ~> %s", str, fpath, *code_name);
    }
    return ret;
}

#define RWOP_TO_STR(op) (op == UCAFS_WRITEOP ? "write" : "read")
afs_int32 SAFSX_readwrite_start(
    /*IN */ struct rx_call * z_call,
    /*IN */ int op,
    /*IN */ char * fpath,
    /*IN */ afs_uint32 max_chunk_size,
    /*IN */ afs_uint32 total_size,
    /*OUT*/ afs_uint32 * id)
{
    int ret;
    xfer_context_t * ctx;

    ctx = fileops_start(op, fpath, max_chunk_size, total_size, &ret);
    if (ctx == NULL) {
        if (ret == -2) {
            uerror("rw: %s, enclave failed", fpath);
            return AFSX_STATUS_ERROR;
        }
        return AFSX_STATUS_NOOP;
    }

    *id = ctx->id;
    uinfo("begin %s: %s (%u, %u) id=%d", RWOP_TO_STR(op), fpath, max_chunk_size,
          total_size, ctx->id);

    return AFSX_STATUS_SUCCESS;
}

afs_int32 SAFSX_readwrite_finish(
    /*IN */ struct rx_call * z_call,
    /*IN */ int id)
{
    uint32_t total;
    int op;
    int ret = fileops_finish(id, &op, &total);
    uinfo("end %s: id=%d, total_bytes=%u", RWOP_TO_STR(op), id, total);

    return ret;
}

afs_int32 SAFSX_readwrite_data(
    /*IN */ struct rx_call * z_call,
    /*IN */ afs_uint32 id,
    /*IN */ afs_uint32 size,
    /*OUT */ int * moredata)
{
    int ret = AFSX_STATUS_ERROR;
    afs_uint32 abytes;

    xfer_context_t * ctx = fileops_get_context(id);
    if (ctx == NULL) {
        uerror("rw failed: id %d could not be found", id);
        goto out;
    }

    if (ctx->buflen < size) {
        uerror("size %d sent is above the cap = %d", size, ctx->buflen);
        goto out;
    }

    if ((abytes = rx_Read(z_call, ctx->buffer, size)) != size) {
        uerror("Read error. expecting: %u, actual: %u (err = %d)", size, abytes,
               rx_Error(z_call));
        goto out;
    }

    ctx->valid_buflen = size;
    // process the data
    fileops_process_data(ctx);

    if ((abytes = rx_Write(z_call, ctx->buffer, size)) != size) {
        uerror("Write error. Expecting: %u, Actual: %u (err = %d)", size,
               abytes, rx_Error(z_call));
        goto out;
    }

    //uinfo("%s: id=%u, len=%u, done=%u", RWOP_TO_STR(ctx->op), id, size,
    //      ctx->completed);

    ret = 0;
out:
    return ret;
}
