#include <stdio.h>
#include <stdlib.h>

#include <uv.h>

#include "third/xdr.h"
#include "third/xdr_prototypes.h"

#include "ucafs_header.h"
#include "cdefs.h"

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
uc_rpc_ping(XDR * xdrs, XDR ** rsp)
{
    int l;

    *rsp = NULL;

    if (!xdr_int(xdrs, &l)) {
        uerror("Could not decode message");
        return -1;
    }

    uinfo("ping: magic = %d", l);

    return 0;
}

static int
uc_rpc_create(XDR * xdrs, XDR ** rsp)
{
    int ret;
    ucafs_entry_type type;
    char * parent_dir = NULL, * name = NULL;

    if (!xdr_string(xdrs, &parent_dir, UCAFS_PATH_MAX) ||
            !xdr_string(xdrs, &name, UCAFS_FNAME_MAX) ||
            !xdr_int(xdrs, (int *)&type)) {
        uerror("uc_rpc_create error decoding message");
        goto out;
    }

    uinfo("create: %s %s", parent_dir, name);

    ret = 0;
out:
    if (parent_dir) {
        free(parent_dir);
    }

    if (name) {
        free(parent_dir);
    }

    return ret;
}

typedef struct xdr_data {
    XDR xdrs;
    uint8_t data[0];
} xdr_data_t;

int
setup_mod()
{
    int len;
    char * data_buf;
    size_t nbytes;
    xdr_data_t * xdr_d = NULL;
    XDR * xdr_out = NULL;
    ucrpc_msg_t m, *msg = &m, rsp;

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
            if ((xdr_d = malloc(sizeof(xdr_data_t) + msg->len)) == NULL) {
                uerror("allocation failed... abort now");
                break;
            }

            xdr_out = NULL;

            fread(xdr_d->data, 1, msg->len, ucafs_mod_fid);
            xdrmem_create(&xdr_d->xdrs, xdr_d->data, msg->len, XDR_DECODE);

            switch (msg->type) {
            case UCAFS_MSG_PING:
                uc_rpc_ping(&xdr_d->xdrs, &xdr_out);
                break;
            case UCAFS_MSG_CREATE:
                uc_rpc_create(&xdr_d->xdrs, &xdr_out);
            default:
                break;
            }

            if (xdr_out == NULL) {
                /* just respond with an empty message */
                rsp = (ucrpc_msg_t){.msg_id = ucrpc__genid(),
                                    .ack_id = msg->msg_id,
                                    .len = 0 };
                len = MSG_SIZE(&rsp);
                nbytes = fwrite(&rsp, 1, len, ucafs_mod_fid);
            } else {
                // TODO
            }

            uinfo("responded, wrote=%zu bytes", nbytes);
            free(xdr_d);
        }
    }

    fclose(ucafs_mod_fid);

    return 0;
}
