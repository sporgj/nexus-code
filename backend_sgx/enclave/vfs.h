#pragma once

#include "nexus_hash.h"

int
nexus_vfs_init(struct nexus_crypto_buf * crypto_buf);

int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash);

void
nexus_vfs_exit();
