#include <stdio.h>
#include <stdlib.h>

#include <uv.h>

#include "third/log.h"
#include "third/xdr.h"
#include "third/xdr_prototypes.h"

#include "cdefs.h"
#include "ucafs_header.h"

#include "uc_rpc.h"

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

typedef struct xdr_inata {
    XDR xdrs;
    uint8_t data[0];
} xdr_data_t;

typedef struct xdr_outsp {
    XDR xdrs;
    ucrpc_msg_t msg;
    uint8_t data[0];
} xdr_rsp_t;

#define XDROUT_DATALEN 64
#define XDROUT_TOTALLEN XDROUT_DATALEN + sizeof(XDR) + sizeof(ucrpc_msg_t)

int
setup_mod()
{
    int len, status;
    size_t nbytes;
    xdr_data_t * x_data = NULL;
    xdr_rsp_t * x_rsp = NULL;
    XDR *xdr_in, *xdr_out;
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
            if ((x_data = malloc(sizeof(xdr_data_t) + msg->len + 10)) == NULL) {
                uerror("allocation failed... abort now");
                break;
            }

            if ((x_rsp = malloc(XDROUT_TOTALLEN)) == NULL) {
                uerror("allocating response.. failed");
                break;
            }

            /* read the data on the wire */
            fread(x_data->data, 1, msg->len, ucafs_mod_fid);

            /* create our XDR data */
            xdr_in = &x_data->xdrs;
            xdr_out = &x_rsp->xdrs;
            xdrmem_create(xdr_in, x_data->data, msg->len, XDR_DECODE);
            xdrmem_create(xdr_out, x_rsp->data, XDROUT_DATALEN, XDR_ENCODE);

            /* dispatch to the corresponding function */
            switch (msg->type) {
            case UCAFS_MSG_PING:
                status = uc_rpc_ping(xdr_in, xdr_out);
                break;
            case UCAFS_MSG_LOOKUP:
            case UCAFS_MSG_FILLDIR:
            case UCAFS_MSG_CREATE:
            case UCAFS_MSG_REMOVE:
                status = uc_rpc_dirops(msg->type, xdr_in, xdr_out);
                break;
            default:
                break;
            }

            /* send the response */
            rsp = &x_rsp->msg;
            nbytes = xdr_out->x_private - xdr_out->x_base;
            *rsp = (ucrpc_msg_t){.msg_id = ucrpc__genid(),
                                 .ack_id = msg->msg_id,
                                 .len = nbytes,
                                 .status = status };
            len = MSG_SIZE(rsp);

            /* send the whole thing */
            nbytes = fwrite(rsp, 1, len, ucafs_mod_fid);

            log_debug("{ uc_mod } status=%d in=(%zu, %d), out=(%zu, %d)", status,
                      MSG_SIZE(msg), msg->len, nbytes, rsp->len);
            free(x_data);
            free(x_rsp);

            status = 0;
        }
    }

    fclose(ucafs_mod_fid);

    return 0;
}
