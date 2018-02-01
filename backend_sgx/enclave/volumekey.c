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

struct nexus_sealed_buf *
nexus_enclave_volumekey_serialize()
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
        if (trusted_ptr == NULL) {
            log_error("nexus_sealed_buf_get FAILED\n");
            goto out;
        }

        output_ptr = nexus_key_to_buf(global_volumekey, trusted_ptr, buf_size);
        if (output_ptr == NULL) {
            log_error("could not copy key into trusted ptr\n");
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
nexus_enclave_volumekey_init(struct nexus_sealed_buf * sealed_buf)
{
    struct nexus_key * unsealed_volumekey = NULL;

    uint8_t * buffer = 0;
    size_t    buflen = 0;

    buffer = nexus_sealed_buf_get(sealed_buf, &buflen);
    if (buffer == NULL) {
        log_error("nexus_sealed_buf_get FAILED\n");
        return -1;
    }

    unsealed_volumekey = nexus_key_from_buf(NEXUS_RAW_128_KEY, buffer, buflen);
    if (unsealed_volumekey == NULL) {
        log_error("could not extract volume key\n");
        return -1;
    }

    __set_volumekey(unsealed_volumekey);

    return 0;
}
