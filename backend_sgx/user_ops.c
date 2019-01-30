#include "internal.h"


#define BUFFER_ARRAY_SIZE   32


static void
print_user_buffer_array(struct nxs_user_buffer * buffer_array, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        printf("- %18s  ", buffer_array[i].name);

        uint8_t * pubkey_hash_buf = buffer_array[i].pubkey_hash;

        for (size_t j = 0; j < NEXUS_PUBKEY_HASHLEN; j++) {
            printf("%02X", pubkey_hash_buf[j]);
        }

        printf("\n");
    }

    fflush(stdout);
}

int
sgx_backend_user_list(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend      * sgx_backend = (struct sgx_backend *)priv_data;

    struct nxs_user_buffer    buffer_array[BUFFER_ARRAY_SIZE]; // TODO revise this

    size_t offset       = 0;
    size_t total_count  = 0;
    size_t result_count = 0;

    int err = -1;
    int ret = -1;

    do {
        err = ecall_user_ls(sgx_backend->enclave_id,
                            &ret,
                            (struct nxs_user_buffer *)&buffer_array,
                            BUFFER_ARRAY_SIZE,
                            offset,
                            &total_count,
                            &result_count);

        if (err || ret) {
            log_error("ecall_user_ls() FAILED. ret=%d, err=%x\n", ret, err);
            return -1;
        }

        if (offset == 0) {
            printf("total user count = %zu\n", total_count);
        }

        print_user_buffer_array(buffer_array, result_count);

        offset += result_count;
    } while(offset < total_count);

    return 0;
}

int
sgx_backend_user_add(struct nexus_volume * volume,
                     char                * username,
                     char                * pubkey_str,
                     void                * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int err = -1;
    int ret = -1;

    err = ecall_user_add(sgx_backend->enclave_id, &ret, username, pubkey_str);

    if (err || ret) {
        log_error("ecall_user_add() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_user_delname(struct nexus_volume * volume, char * username, void * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int err = -1;
    int ret = -1;

    err = ecall_user_remove_username(sgx_backend->enclave_id, &ret, username);

    if (err || ret) {
        log_error("ecall_user_remove_username() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_user_delkey(struct nexus_volume * volume, char * pubkey, void * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int err = -1;
    int ret = -1;

    err = ecall_user_remove_pubkey(sgx_backend->enclave_id, &ret, pubkey);

    if (err || ret) {
        log_error("ecall_user_remove_pubkey() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_user_findname(struct nexus_volume * volume, char * username, void * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    struct nxs_user_buffer user_buffer;

    int err = -1;
    int ret = -1;

    err = ecall_user_find_username(sgx_backend->enclave_id, &ret, username, &user_buffer);

    if (err || ret) {
        log_error("ecall_user_find_username() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    print_user_buffer_array(&user_buffer, 1);

    return 0;
}

int
sgx_backend_user_findkey(struct nexus_volume * volume, char * pubkey, void * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    struct nxs_user_buffer user_buffer;

    int err = -1;
    int ret = -1;

    err = ecall_user_find_pubkey(sgx_backend->enclave_id, &ret, pubkey, &user_buffer);

    if (err || ret) {
        log_error("ecall_user_find_pubkey() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    print_user_buffer_array(&user_buffer, 1);

    return 0;
}
