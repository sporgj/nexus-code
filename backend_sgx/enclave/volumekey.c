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
    struct nexus_sealed_buf * sealed_buf = NULL;

    int key_size = 0;

    key_size = nexus_key_bytes(global_volumekey);
    if (key_size <= 0) {
        log_error("could not get valid key_size for volumekey\n");
        return NULL;
    }


    sealed_buf = nexus_sealed_buf_new(key_size);

    {
        uint8_t * trusted_ptr = NULL;
        uint8_t * output_ptr  = NULL;

        size_t buf_size = 0;

        int ret = 1;


        trusted_ptr = nexus_sealed_buf_get(sealed_buf, &buf_size);

        output_ptr = nexus_key_to_buf(global_volumekey, trusted_ptr, buf_size);
        if (output_ptr == NULL) {
            log_error("could not key into trusted ptr\n");
            goto out;
        }

        ret = nexus_sealed_buf_put(sealed_buf);
        if (ret != 0) {
            log_error("nexus_sealed_buf_put FAILED\n");
            goto out;
        }
    }

    return sealed_buf;
out:
    if (sealed_buf) {
        nexus_sealed_buf_free(sealed_buf);
    }

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
    struct nexus_key * unsealed_volumekey = NULL;

    size_t buf_size = 0;

    unsealed_volumekey = (struct nexus_key *)nexus_sealed_buf_get(sealed_buf, &buf_size);
    if (unsealed_volumekey == NULL) {
        log_error("nexus_sealed_buf_get FAILED\n");
        return -1;
    }

    // we clone because the sealed buffer "owns" the unsealed_volumkey buffer
    __set_volumekey(nexus_clone_key(unsealed_volumekey));

    return 0;
}
