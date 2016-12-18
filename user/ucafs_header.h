#pragma once
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/types.h>
#include <linux/mutex.h>
#else
#include <stdint.h>
#endif

typedef uint16_t mid_t;

typedef enum {
    UCAFS_MSG_PING
} uc_msg_type_t;

typedef struct {
    uc_msg_type_t type;
    uint16_t msg_id; /* the ID of the message */
    uint16_t ack_id; /* the message it responds to */
    uint32_t len; /* the length of the payload */
    char payload[0];
} ucrpc_msg_t;

#define MSG_SIZE(msg) sizeof(ucrpc_msg_t) + (((ucrpc_msg_t *)msg)->len)

extern mid_t msg_counter;

#ifdef __KERNEL__

static DEFINE_MUTEX(mut_msg_counter);

// TODO use mutex here
static inline mid_t ucrpc__genid(void) {
    mid_t counter;
    mutex_lock_interruptible(&mut_msg_counter);
    counter = (++msg_counter);
    mutex_unlock(&mut_msg_counter);

    return counter;
}

#endif
