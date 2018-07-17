#include "enclave_internal.h"

// the sealing key used in protecting volumekeys
struct nexus_volume * global_volume             = NULL;

// TODO: make this per-instance configurable
size_t                global_chunk_size         = NEXUS_CHUNK_SIZE;

size_t                global_log2chunk_size     = 0;

struct nexus_heap   * global_heap               = NULL;

nexus_uid_t           global_user_id            = 0;



int
ecall_init_enclave(struct nexus_volume  * volume,
                   struct nexus_heap    * heap)
{
    global_volume      = volume;

    global_heap        = heap;

    if (buffer_layer_init() != 0) {
        return -1;
    }

    if (nexus_vfs_init() != 0) {
        buffer_layer_exit();
        return -1;
    }

    {
        size_t temp = global_chunk_size;
        size_t pow2 = 0;

        while (temp > 0) {
            pow2 += 1;
            temp >>= 1;
        }

        global_log2chunk_size = pow2 - 1;
    }

    return 0;
}

int
nexus_verfiy_pubkey(struct nexus_hash * user_pubkey_hash)
{
    struct nexus_user * user = NULL;

    user = nexus_usertable_find_pubkey(global_supernode->usertable, user_pubkey_hash);

    if (user == NULL) {
        return -1;
    }

    global_user_id = user->user_id;

    return 0;
}
