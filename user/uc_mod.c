#include <stdio.h>
#include <stdlib.h>

#include <uv.h>

#include "third/log.h"
#include "third/xdr.h"
#include "third/xdr_prototypes.h"

#include "cdefs.h"
#include "ucafs_header.h"

#define UCAFS_MOD_FILE "/dev/ucafs_mod"

static FILE * ucafs_mod_fid = NULL;

mid_t msg_counter;
uv_mutex_t mut_msg_counter;

static inline mid_t
ucrpc__genid(void)
{
    mid_t counter;
    uv_mutex_lock(&mut_msg_counter);
    counter = (++msg_counter);
    uv_mutex_unlock(&mut_msg_counter);

    return counter;
}

static int
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

static int
uc_rpc_create(XDR * xdrs, XDR * rsp)
{
    int ret;
    ucafs_entry_type type;
    char *parent_dir = NULL, *name = NULL, *shdw_name = NULL;

    if (!xdr_string(xdrs, &parent_dir, UCAFS_PATH_MAX)
        || !xdr_string(xdrs, &name, UCAFS_FNAME_MAX)
        || !xdr_int(xdrs, (int *)&type)) {
        uerror("uc_rpc_create error decoding message");
        goto out;
    }

    if (dirops_new1(parent_dir, name, &shdw_name)) {
        log_error("[create] %s/%s FAILED", parent_dir, name);
        goto out;
    }

    log_info("[create] %s/%s -> %s", parent_dir, name, shdw_name);

    /* now start encoding the response */
    if (!xdr_string(rsp, &shdw_name, UCAFS_FNAME_MAX)) {
        uerror("ERROR encoding create response");
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

typedef struct xdr_data {
    XDR xdrs;
    uint8_t data[0];
} xdr_data_t;

typedef struct xdr_rsp {
    XDR xdrs;
    ucrpc_msg_t msg;
    uint8_t data[0];
} xdr_rsp_t;

#define MAX_XDR_SIZE1 128
#define XDR_RSP_SIZE(sz) sz - sizeof(XDR) - sizeof(ucrpc_msg_t)

int
setup_mod()
{
    int len, status;
    char * data_buf;
    size_t nbytes;
    xdr_data_t * x_data = NULL;
    xdr_rsp_t * x_rsp = NULL;
    XDR *xdr_r, *xdr_d;
    ucrpc_msg_t m, *msg = &m, *rsp;

    uv_mutex_init(&mut_msg_counter);

    if (ucafs_mod_fid) {
        return 0;
    }

    if ((ucafs_mod_fid = fopen(UCAFS_MOD_FILE, "rb+")) == NULL) {
        uerror("opening '%s' failed", UCAFS_MOD_FILE);
        perror("Error: ");
        return -1;
    }

    while (1) {
        nbytes = fread(msg, 1, sizeof(ucrpc_msg_t), ucafs_mod_fid);
        if (nbytes == sizeof(ucrpc_msg_t)) {
            if ((x_data = malloc(sizeof(xdr_data_t) + msg->len)) == NULL) {
                uerror("allocation failed... abort now");
                break;
            }

            if ((x_rsp = malloc(sizeof(MAX_XDR_SIZE1))) == NULL) {
                uerror("allocating response.. failed");
                break;
            }

            /* read the data on the wire */
            fread(x_data->data, 1, msg->len, ucafs_mod_fid);

            /* create our XDR data */
            xdrmem_create(&x_data->xdrs, x_data->data, msg->len, XDR_DECODE);
            xdrmem_create(&x_rsp->xdrs, x_rsp->data,
                          XDR_RSP_SIZE(MAX_XDR_SIZE1), XDR_ENCODE);

            /* dispatch to the corresponding function */
            xdr_d = &x_data->xdrs;
            xdr_r = &x_rsp->xdrs;
            switch (msg->type) {
            case UCAFS_MSG_PING:
                status = uc_rpc_ping(xdr_d, xdr_r);
                break;
            case UCAFS_MSG_CREATE:
                status = uc_rpc_create(xdr_d, xdr_r);
                break;
            default:
                break;
            }

            /* send the response */
            rsp = &x_rsp->msg;
            nbytes = xdr_r->x_private - xdr_r->x_base;
            *rsp = (ucrpc_msg_t){.msg_id = ucrpc__genid(),
                                 .ack_id = msg->msg_id,
                                 .len = nbytes,
                                 .status = status };
            len = MSG_SIZE(rsp);

            /* send the whole thing */
            nbytes = fwrite(rsp, 1, len, ucafs_mod_fid);

            uinfo("responded, wrote=%zu bytes, msg_len = %d", nbytes, len);
            free(x_data);
            free(x_rsp);
        }
    }

    fclose(ucafs_mod_fid);

    return 0;
}
