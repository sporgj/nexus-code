#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

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

#include "acl.h"
#include "vfs.h"
#include "volumekey.h"
#include "crypto.h"
#include "supernode.h"
#include "user.h"
#include "dirnode.h"
#include "filenode.h"

#include <nexus_volume.h>
#include <nexus_fs.h>
#include <nexus_log.h>
#include <nexus_mac.h>
#include <nexus_key.h>
#include <nexus_hash.h>
#include <nexus_uuid.h>
#include <nexus_util.h>
#include <nexus_list.h>

#define ocall_debug(str) \
    ocall_print("enclave> " str "\n")


extern struct nexus_key * global_volumekey;

extern struct nexus_supernode * global_supernode;

extern nexus_uid_t        global_user_id;

extern size_t global_chunk_size;
extern size_t global_log2chunk_size;

// pointer to the backend info. Used in ocalls
struct nexus_volume * global_volume;
