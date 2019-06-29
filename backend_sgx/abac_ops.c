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

    struct nxs_attribute_schema schema_array[_ARRAY_LEN];

    size_t offset      = 0;
    size_t total_size  = 0;
    size_t result_size = 0;

    int ret = -1;
    int err = -1;

    do {
        err = ecall_abac_attribute_ls(
            backend->enclave_id, &ret, schema_array, _ARRAY_LEN, offset, &total_size, &result_size);

        if (ret || err) {
            log_error("ecall_abac_attribute_ls() FAILED. err=%x, ret=%d\n", err, ret);
            return -1;
        }

        if (offset == 0) {
            printf("ATTRIBUTE COUNT = %zu\n===\n", total_size);
        }

        for (size_t i = 0; i < result_size; i++) {
            printf("\t %s [%s]\n", schema_array[i].schema_str, schema_array[i].type_str);
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
    int err = -1;

    err = ecall_abac_user_attribute_revoke(backend->enclave_id, &ret, username, attribute_name);

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
            printf("\t %s [%s]\n", pair_array[i].schema_str, pair_array[i].val_str);
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
            printf("\t %s [%s]\n", pair_array[i].schema_str, pair_array[i].val_str);
        }

        offset += result_size;
    } while (offset < total_size);

    return 0;
}


int
sgx_backend_abac_policy_add(char                * policy_string,
                            struct nexus_uuid   * uuid,
                            struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_policy_add(backend->enclave_id, &ret, policy_string, uuid);

    if (err || ret) {
        log_error("ecall_abac_policy_add() FAILED\n");
        return -1;
    }

    return 0;
}


int
sgx_backend_abac_policy_del(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_policy_del(backend->enclave_id, &ret, uuid);

    if (err || ret) {
        log_error("ecall_abac_policy_del() FAILED\n");
        return -1;
    }

    return 0;
}


static void
__print_policy_buffer(struct nxs_policy_rule * rules_buffer, size_t result_count)
{
    for (size_t i = 0; i < result_count; i++) {
        char * uuid_str = nexus_uuid_to_hex(&rules_buffer->rule_uuid);

        printf("[%s]\n", uuid_str);
        printf("%s\n\n", rules_buffer->rule_str);

        nexus_free(uuid_str);

        rules_buffer
            = (struct nxs_policy_rule *)(((uint8_t *)rules_buffer) + rules_buffer->total_len);
    }
}

int
sgx_backend_abac_policy_ls(struct nexus_volume * volume)
{
    static size_t buf_capacity = 4096;

    struct sgx_backend     * backend      = __sgx_backend_from_volume(volume);
    struct nxs_policy_rule * rules_buffer = NULL;

    size_t offset       = 0;
    size_t total_count  = 0;
    size_t result_count = 0;


    rules_buffer = nexus_malloc(buf_capacity);

    do {
        int ret = -1;
        int err = ecall_abac_policy_ls(backend->enclave_id,
                                       &ret,
                                       rules_buffer,
                                       buf_capacity,
                                       offset,
                                       &total_count,
                                       &result_count);

        if (err || ret) {
            log_error("ecall_abac_policy_ls() FAILED\n");
            goto out_err;
        }

        __print_policy_buffer(rules_buffer, result_count);

        offset += result_count;
    } while (offset < total_count);

    nexus_free(rules_buffer);

    return 0;
out_err:
    nexus_free(rules_buffer);
    return -1;
}

int
sgx_backend_abac_print_facts(struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_print_facts(backend->enclave_id, &ret);

    if (ret || err) {
        log_error("ecall_abac_print_facts() FAILED\n");
        return -1;
    }

    return 0;
}

int
sgx_backend_abac_print_rules(struct nexus_volume * volume)
{
    struct sgx_backend * backend = __sgx_backend_from_volume(volume);

    int ret = -1;
    int err = ecall_abac_print_rules(backend->enclave_id, &ret);

    if (ret || err) {
        log_error("ecall_abac_print_rules() FAILED\n");
        return -1;
    }

    return 0;
}
