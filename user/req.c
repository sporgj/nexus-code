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

afs_int32 SAFSX_fpush(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_uint64 blocklength,
    /*IN */ afs_uint64 filelength)
{
    int ret = -1;
    afs_uint64 remaining_bytes = filelength, nbytes = blocklength;
    store_ctx_t * ctx = start_upload(fpath, blocklength, filelength);
    if (ctx == NULL) {
        uerror("Error starting upload");
        goto out;
    }

    // start receiving data
    while (remaining_bytes) {
        nbytes = remaining_bytes > blocklength ? blocklength : remaining_bytes;

        // read
        nbytes = rx_Read(z_call, ctx->buffer, nbytes);

        if (!nbytes) {
            uerror("Error during transmission");
            goto out;
        }

        // process the data
        ctx->len = nbytes;
        process_upload_data(ctx);

        if (rx_Write(z_call, ctx->buffer, ctx->len) != nbytes) {
            uerror("Error writing response");
            goto out;
        }

        remaining_bytes -= nbytes;
    }

    printf("fpush: Completed %llu bytes\n", filelength);

    ret = 0;
out:
    return ret;
}

afs_int32 SAFSX_fpull(
    /*IN */ struct rx_call * z_call,
    /*IN */ char * fpath,
    /*IN */ afs_uint64 chunklength,
    /*IN */ afs_uint64 filelength)
{
    return 0;
}
