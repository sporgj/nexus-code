#include "cdefs.h"
#include "afsx.h"
#include "dirops.h"
#include "fileops.h"

#define N_SECURITY_OBJECTS 1

int setup_rx(int port)
{
    struct rx_securityClass *(security_objs[N_SECURITY_OBJECTS]);
    struct rx_service * service;
    int ret = 1;

    if (rx_Init(port == 0 ? AFSX_SERVER_PORT : port) < 0) {
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

    uinfo("Waiting for connections...");
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

afs_int32 SAFSX_fnew(struct rx_call * z_call, char * path, char ** crypto_fname)
{
    int ret = fops_new(path, crypto_fname);
    if (ret) {
        *crypto_fname = EMPTY_STR_HEAP;
    } else {
        printf("> fnew: %s ~> %s\n", path, *crypto_fname);
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
        printf("> freal: %s ~> %s\n", fake_name, *plain_name);
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

afs_int32 SAFSX_fremove(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*OUT */ char ** code_name_str)
{
    int ret = fops_remove(fpath, code_name_str);
    if (ret) {
        *code_name_str = EMPTY_STR_HEAP;
    } else {
        printf("fremove: %s ~> %s\n", fpath, *code_name_str);
    }
    return ret;
}

afs_int32 SAFSX_start_upload(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_uint32 max_chunk_size,
    /*IN */ afs_uint64 total_size,
    /*OUT*/ afs_uint32 * upload_id)
{
    store_ctx_t * ctx = start_upload(fpath, max_chunk_size, total_size);
    if (ctx == NULL) {
        return AFSX_STATUS_NOOP;
    }
    *upload_id = ctx->id;
    printf("start_upload: %s (%u, %llu), upload_id=%d\n", fpath, max_chunk_size,
           total_size, ctx->id);
    return AFSX_STATUS_SUCCESS;
}

afs_int32 SAFSX_end_upload(
	/*IN */ struct rx_call *z_call,
	/*IN */ int upload_id)
{
    // TODO
    return 0;
}

afs_int32 SAFSX_upload_file(
    /*IN */ struct rx_call * z_call,
    /*IN */ afs_uint32 upload_id,
    /*IN */ afs_uint32 chunk_size)
{
    int ret = AFSX_STATUS_NOOP;
    afs_uint32 abytes;

    store_ctx_t * ctx = get_upload_buffer(upload_id);
    if (ctx == NULL) {
        ret = AFSX_STATUS_ERROR;
        uerror("Upload id: %d could not be found", upload_id);
        goto out;
    }

    if (ctx->cap < chunk_size) {
        uerror("Chunk size %d sent is above the cap = %d", chunk_size,
               ctx->cap);
        ret = AFSX_STATUS_ERROR;
        goto out;
    }

    if ((abytes = rx_Read(z_call, ctx->buffer, chunk_size)) != chunk_size) {
        uerror("Read error. expecting: %u, actual: %u (err = %d)", chunk_size,
               abytes, rx_Error(z_call));
        goto out;
    }

    ctx->len = chunk_size;
    // process the data
    process_upload_data(ctx);

    if ((abytes = rx_Write(z_call, ctx->buffer, ctx->len)) != chunk_size) {
        uerror("Write error. Expecting: %u, Actual: %u (err = %d)", chunk_size,
               abytes, rx_Error(z_call));
        goto out;
    }

    ret = 0;
out:
    return ret;
}

afs_int32 SAFSX_download_file(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_uint64 chunklength,
    /*IN */ afs_uint64 filelength)
{
    return 0;
}
