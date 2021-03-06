#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <sgx_spinlock.h>

#include <assert.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

#include "nexus_enclave_t.h"

#include "buffer_layer.h"

#include "data_buffer.h"
#include "crypto_buffer.h"
#include "raw_buffer.h"
#include "key_buffer.h"

#include "vfs.h"
#include "volumekey.h"
#include "crypto.h"
#include "supernode.h"
#include "user.h"
#include "metadata.h"
#include "dentry.h"
#include "dirnode.h"
#include "bucket.h"
#include "filenode.h"
#include "file_crypto.h"
#include "hardlink_table.h"

#include <nexus_volume.h>
#include <nexus_fs.h>
#include <nexus_log.h>
#include <nexus_mac.h>
#include <nexus_key.h>
#include <nexus_hash.h>
#include <nexus_uuid.h>
#include <nexus_util.h>
#include <nexus_list.h>
#include <nexus_lru.h>
#include <nexus_heap.h>
#include <nexus_hashtable.h>

#include "libnexus_trusted/offsetof.h"

#define ocall_debug(str) \
    ocall_print("enclave> " str "\n")


extern struct nexus_volume         * global_volume;

extern struct nexus_key            * global_volumekey;

extern struct nexus_supernode      * global_supernode;

extern struct nexus_metadata       * global_supernode_metadata;


extern struct nexus_heap           * global_heap;

extern struct nxs_tick_tok         * global_tick_tok;


extern nexus_uid_t                   global_user_id;

extern struct nexus_user           * global_user_struct;


extern size_t                        global_chunk_size;
extern size_t                        global_log2chunk_size;


extern sgx_spinlock_t                vfs_ops_lock;


/**
 * Verifies the pubkey
 * @param user_pubkey_hash
 * @return 0
 */
int
nexus_verfiy_pubkey(struct nexus_hash * user_pubkey_hash);

bool
nexus_enclave_is_current_user_owner();

void
enclave_get_ticktock(uint64_t * const nsec);
