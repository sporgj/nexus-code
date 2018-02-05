#pragma once

#include "nexus_hash.h"

#include "dirnode.h"

int
nexus_vfs_init();

void
nexus_vfs_deinit();

int
nexus_vfs_mount(struct nexus_crypto_buf * crypto_buf);

int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash);

void
nexus_vfs_exit();