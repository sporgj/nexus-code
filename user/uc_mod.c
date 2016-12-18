#include <stdio.h>
#include <stdlib.h>

#include <uv.h>

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

int
setup_mod()
{
    char buf[50];
    size_t nbytes;
    ucrpc_msg_t * msg = (ucrpc_msg_t *)buf;

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
            fread(&msg->payload, 1, msg->len, ucafs_mod_fid);
            if (msg->type == UCAFS_MSG_PING) {
                ucrpc_msg_t rsp = {.msg_id = ucrpc__genid(),
                                   .ack_id = msg->msg_id,
                                   .len = 0 };

                int len = MSG_SIZE(&rsp);

                // lets respond
                nbytes = fwrite(&rsp, 1, len, ucafs_mod_fid);
                uinfo("Got a ping... write=%zu bytes", nbytes);
            }
        }
    }

    return 0;
}
