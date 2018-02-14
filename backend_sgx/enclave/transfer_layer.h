#pragma once

#include "filenode.h"

typedef enum {
    XFER_ENCRYPT,
    XFER_DECRYPT
} xfer_op_t;

void
transfer_layer_init();

void
transfer_layer_exit();

/**
 * Creates a new transfer context.
 * @param offset inside the file. Must be at chunk boundary
 * @param filenode is the associated filenode
 * @return -1 on FAILURE
 */
int
transfer_layer_new(size_t offset, struct nexus_filenode * filenode);

/**
 * Processes external buffer
 * @param xfer_id
 * @param external_addr
 * @param buflen
 *
 * @return 0 for success
 */
int
transfer_layer_process(int xfer_id, uint8_t * external_addr, size_t buflen);
