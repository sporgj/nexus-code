#include "internal.h"

int
sgx_backend_abac_attribute_add(char                * attribute_name,
                               char                * attribute_type,
                               struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_attribute_add(backend->enclave_id, &ret, attribute_name, attribute_type);

    if (err || ret) {
        log_error("ecall_abac_attribute_add() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_attribute_del(char * attribute_name, struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_attribute_del(backend->enclave_id, &ret, attribute_name);

    if (err || ret) {
        log_error("ecall_abac_attribute_del() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_attribute_ls(struct nexus_volume * volume)
{
    static size_t _ARRAY_LEN = (50);

    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    struct nxs_attribute_term term_array[_ARRAY_LEN];

    size_t offset      = 0;
    size_t total_size  = 0;
    size_t result_size = 0;

    int ret = -1;
    int err = -1;

    do {
        err = ecall_abac_attribute_ls(
            backend->enclave_id, &ret, term_array, _ARRAY_LEN, offset, &total_size, &result_size);

        if (ret || err) {
            log_error("ecall_abac_attribute_ls() FAILED. err=%x, ret=%d\n", err, ret);
            return -1;
        }

        if (offset == 0) {
            printf("ATTRIBUTE COUNT = %zu\n===\n", total_size);
        }

        for (size_t i = 0; i < result_size; i++) {
            printf("\t %s [%s]\n", term_array[i].term_str, term_array[i].type_str);
        }

        offset += result_size;
    } while (offset < total_size);

    return 0;
}

int
sgx_backend_abac_user_grant(char                * username,
                            char                * attribute_name,
                            char                * attribute_val,
                            struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_user_attribute_grant(
        backend->enclave_id, &ret, username, attribute_name, attribute_val);

    if (err || ret) {
        log_error("ecall_abac_user_attribute_grant() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_user_revoke(char * username, char * attribute_name, struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_user_attribute_revoke(backend->enclave_id, &ret, username, attribute_name);

    if (err || ret) {
        log_error("ecall_abac_user_attribute_revoke() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_user_ls(char * username, struct nexus_volume * volume)
{
    static size_t _ARRAY_LEN = (50);

    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    struct nxs_attribute_pair pair_array[_ARRAY_LEN];

    size_t offset      = 0;
    size_t total_size  = 0;
    size_t result_size = 0;

    int ret = -1;
    int err = -1;

    do {
        err = ecall_abac_user_attribute_ls(backend->enclave_id,
                                           &ret,
                                           username,
                                           pair_array,
                                           _ARRAY_LEN,
                                           offset,
                                           &total_size,
                                           &result_size);

        if (ret || err) {
            log_error("ecall_abac_user_attribute_ls() FAILED. err=%x, ret=%d\n", err, ret);
            return -1;
        }

        if (offset == 0) {
            printf("ATTRIBUTE COUNT = %zu\n", total_size);
        }

        for (size_t i = 0; i < result_size; i++) {
            printf("\t %s [%s]\n", pair_array[i].term_str, pair_array[i].val_str);
        }

        offset += result_size;
    } while (offset < total_size);

    return 0;
}

int
sgx_backend_abac_object_grant(char                * path,
                              char                * attribute_name,
                              char                * attribute_val,
                              struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_object_attribute_grant(
        backend->enclave_id, &ret, path, attribute_name, attribute_val);

    if (err || ret) {
        log_error("ecall_abac_object_attribute_grant() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_object_revoke(char                * path,
                               char                * attribute_name,
                               struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_object_attribute_revoke(backend->enclave_id, &ret, path, attribute_name);

    if (err || ret) {
        log_error("ecall_abac_object_attribute_revoke() FAILED. err=%x, ret=%d\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_object_ls(char * path, struct nexus_volume * volume)
{
    static size_t _ARRAY_LEN = (50);

    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    struct nxs_attribute_pair pair_array[_ARRAY_LEN];

    size_t offset      = 0;
    size_t total_size  = 0;
    size_t result_size = 0;

    int ret = -1;
    int err = -1;

    do {
        err = ecall_abac_object_attribute_ls(backend->enclave_id,
                                             &ret,
                                             path,
                                             pair_array,
                                             _ARRAY_LEN,
                                             offset,
                                             &total_size,
                                             &result_size);

        if (ret || err) {
            log_error("ecall_abac_object_attribute_ls() FAILED. err=%x, ret=%d\n", err, ret);
            return -1;
        }

        if (offset == 0) {
            printf("ATTRIBUTE COUNT = %zu\n===\n", total_size);
        }

        for (size_t i = 0; i < result_size; i++) {
            printf("\t %s [%s]\n", pair_array[i].term_str, pair_array[i].val_str);
        }

        offset += result_size;
    } while (offset < total_size);

    return 0;
}
