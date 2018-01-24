#include "internal.h"

struct nexus_key * global_volumekey = NULL;

static void
__set_volumekey(struct nexus_key * volumekey)
{
    if (global_volumekey) {
        nexus_free_key(global_volumekey);
        nexus_free(global_volumekey);
    }

    global_volumekey = volumekey;
}

int
enclave_volumekey_gen()
{
    struct nexus_key * volumekey = NULL;

    volumekey = nexus_create_key(NEXUS_RAW_128_KEY);

    if (!volumekey) {
        log_error("could not generate volumekey");
        return -1;
    }

    __set_volumekey(volumekey);

    return 0;
}

void
enclave_volumekey_clear()
{
    __set_volumekey(NULL);
}

struct nexus_sealed_buf *
enclave_volumekey_serialize()
{
    // TODO
    return NULL;
}

/**
 * parses a volumekey and sets it as the global volumekey
 * @param sealed_buf
 * @return 0 on success
 */
int
enclave_volumekey_init(struct nexus_sealed_buf * sealed_buf)
{
    // TODO
    return -1;
}
