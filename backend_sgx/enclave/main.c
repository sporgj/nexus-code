#include "enclave_internal.h"

// the sealing key used in protecting volumekeys
struct nexus_volume * global_volume             = NULL;

// TODO: make this per-instance configurable
size_t                global_chunk_size         = NEXUS_CHUNK_SIZE;

size_t                global_log2chunk_size     = 0;

struct nexus_heap   * global_heap               = NULL;

struct nxs_tick_tok * global_tick_tok           = NULL;

nexus_uid_t           global_user_id            = NEXUS_INVALID_USER_ID;

struct nexus_user   * global_user_struct        = NULL;

sgx_spinlock_t        vfs_ops_lock              = SGX_SPINLOCK_INITIALIZER;



// ============================================
// --------------------------------------------
// ============================================
// Small hack for getting the memory usage from the enclave heap

struct mallinfo {
    int arena;     /* Non-mmapped space allocated (bytes) */
    int ordblks;   /* Number of free chunks */
    int smblks;    /* Number of free fastbin blocks */
    int hblks;     /* Number of mmapped regions */
    int hblkhd;    /* Space allocated in mmapped regions (bytes) */
    int usmblks;   /* Maximum total allocated space (bytes) */
    int fsmblks;   /* Space in freed fastbin blocks (bytes) */
    int uordblks;  /* Total allocated space (bytes) */
    int fordblks;  /* Total free space (bytes) */
    int keepcost;  /* Top-most, releasable space (bytes) */
};

extern struct mallinfo dlmallinfo();

// ============================================
// --------------------------------------------
// ============================================


int
ecall_init_enclave(struct nexus_volume  * volume,
                   struct nexus_heap    * heap,
                   struct nxs_tick_tok  * tick_tok)
{
    global_volume      = volume;
    global_heap        = heap;
    global_tick_tok    = tick_tok;

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
ecall_export_telemetry(struct nxs_telemetry * telemetry_out)
{
    abac_export_telemetry(telemetry_out);

    struct mallinfo malloc_info = dlmallinfo();

    telemetry_out->total_allocated_bytes = malloc_info.uordblks;

    return 0;
}

bool
nexus_enclave_is_current_user_owner()
{
    return global_user_id == NEXUS_ROOT_USER;
}

int
nexus_verfiy_pubkey(pubkey_hash_t * user_pubkey_hash)
{
    struct nexus_usertable * global_usertable = nexus_vfs_acquire_user_table(NEXUS_FREAD);

    if (global_usertable == NULL) {
        log_error("nexus_vfs_acquire_user_table() FAILED\n");
        return -1;
    }

    global_user_struct = nexus_usertable_find_pubkey_hash(global_usertable, user_pubkey_hash);

    nexus_vfs_release_user_table();

    if (global_user_struct == NULL) {
        return -1;
    }

    global_user_id = global_user_struct->user_id;

    return 0;
}

void
enclave_get_ticktock(uint64_t * const nsec)
{
    struct T {
        uint32_t lower;
        uint32_t higher;
    } * const tmp = (struct T * const)nsec;

    asm volatile("lock cmpxchg8b %[ptr] \n"
                 : "=a"(tmp->lower), "=d"(tmp->higher)
                 : "a"((uint64_t)0),
                   "b"((uint64_t)0),
                   "c"((uint64_t)0),
                   "d"((uint64_t)0),
                   [ptr] "m"(global_tick_tok->nsec));
}
