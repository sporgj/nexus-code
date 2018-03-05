#include "../enclave_internal.h"

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
nexus_enclave_volumekey_generate()
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
nexus_enclave_volumekey_clear()
{
    __set_volumekey(NULL);
}

struct nexus_key_buffer *
nexus_enclave_volumekey_serialize()
{
    struct nexus_key_buffer * key_buffer = NULL;

    key_buffer = key_buffer_seal(global_volumekey);

    if (key_buffer == NULL) {
        log_error("could not create key buffer\n");
        return NULL;
    }

    return key_buffer;
}

/**
 * parses a volumekey and sets it as the global volumekey
 * @param sealed_buf
 * @return 0 on success
 */
int
nexus_enclave_volumekey_load(struct nexus_key_buffer * key_buffer)
{
    struct nexus_key * unsealed_volumekey = NULL;

    unsealed_volumekey = key_buffer_extract128(key_buffer);

    if (unsealed_volumekey == NULL) {
        log_error("key_buffer_extract128 FAILED\n");
        return -1;
    }

    __set_volumekey(unsealed_volumekey);

    return 0;
}
