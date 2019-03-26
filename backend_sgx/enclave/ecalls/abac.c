#include "../enclave_internal.h"


int
ecall_abac_attribute_add(char * attribute_name_IN, char * attribute_type_str_IN)
{
    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FRDWR);

    attribute_type_t attribute_type;

    if (attribute_store == NULL) {
        log_error("abac_acquire_attribute_store() FAILED\n");
        return -1;
    }

    attribute_type = attribute_type_from_str(attribute_type_str_IN);

    if (attribute_type == -1) {
        log_error("could not get attribute_type (%s)\n", attribute_type_str_IN);
        goto err;
    }

    if (attribute_store_add(attribute_store, attribute_name_IN, attribute_type)) {
        log_error("could not add attribute: `%s`\n", attribute_name_IN);
        goto err;
    }

    if (abac_flush_attribute_store()) {
        log_error("abac_flush_attribute_store() FAILED\n");
        return -1;
    }

    return 0;
err:
    abac_release_attribute_store();

    return -1;
}

int
ecall_abac_attribute_del(char * attribute_name_IN)
{
    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FRDWR);

    attribute_type_t attribute_type;

    if (attribute_store == NULL) {
        log_error("abac_acquire_attribute_store() FAILED\n");
        return -1;
    }

    if (attribute_store_del(attribute_store, attribute_name_IN)) {
        log_error("could not delete attribute: `%s`\n", attribute_name_IN);
        goto err;
    }

    if (abac_flush_attribute_store()) {
        log_error("abac_flush_attribute_store() FAILED\n");
        return -1;
    }

    return 0;
err:
    abac_release_attribute_store();

    return -1;
}

int
ecall_abac_attribute_ls(struct nxs_attribute_term * attribute_term_array_out,
                        size_t                      attribute_term_array_capacity,
                        size_t                      offset,
                        size_t                    * total_count_out,
                        size_t                    * result_count_out)
{

    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FRDWR);

    if (attribute_store == NULL) {
        log_error("abac_acquire_attribute_store() FAILED\n");
        return -1;
    }

    if (UNSAFE_attribute_store_export_terms(attribute_store,
                                            attribute_term_array_out,
                                            attribute_term_array_capacity,
                                            offset,
                                            total_count_out,
                                            result_count_out)) {
        log_error("UNSAFE_attribute_store_export_terms FAILED\n");
        goto err;
    }

    abac_release_attribute_store();

    return 0;
err:
    abac_release_attribute_store();

    return -1;
}

int
ecall_abac_user_attribute_grant(char * username_IN,
                                char * attribute_name_IN,
                                char * attribute_value_IN)
{
    struct user_profile * user_profile = abac_get_user_profile(username_IN, NEXUS_FRDWR);

    if (user_profile == NULL) {
        log_error("abac_get_user_profile() FAILED\n");
        return -1;
    }

    if (user_profile_grant_attribute(user_profile, attribute_name_IN, attribute_value_IN)) {
        abac_put_user_profile(user_profile);
        log_error("user_profile_grant_attribute() FAILED\n");
        return -1;
    }

    if (abac_put_user_profile(user_profile)) {
        log_error("abac_put_user_profile() FAILED\n");
        return -1;
    }

    return 0;
}

int
ecall_abac_user_attribute_revoke(char * username_IN, char * attribute_name_IN)
{
    struct user_profile * user_profile = abac_get_user_profile(username_IN, NEXUS_FRDWR);

    if (user_profile == NULL) {
        log_error("abac_get_user_profile() FAILED\n");
        return -1;
    }

    if (user_profile_revoke_attribute(user_profile, attribute_name_IN)) {
        abac_put_user_profile(user_profile);
        log_error("user_profile_grant_attribute() FAILED\n");
        return -1;
    }

    if (abac_put_user_profile(user_profile)) {
        log_error("abac_put_user_profile() FAILED\n");
        return -1;
    }

    return 0;
}

int
ecall_abac_user_attribute_ls(char                      * username_IN,
                             struct nxs_attribute_pair * attribute_pair_array,
                             size_t                      attribute_pair_capacity,
                             size_t                      offset,
                             size_t                    * result_count,
                             size_t                    * total_count)
{
    struct user_profile * user_profile = abac_get_user_profile(username_IN, NEXUS_FREAD);

    if (user_profile == NULL) {
        log_error("abac_get_user_profile() FAILED\n");
        return -1;
    }

    if (UNSAFE_user_profile_attribute_ls(user_profile,
                                         attribute_pair_array,
                                         attribute_pair_capacity,
                                         offset,
                                         result_count,
                                         total_count)) {
        log_error("UNSAFE_user_profile_attribute_ls FAILED\n");
        goto err;
    }

    abac_put_user_profile(user_profile);

    return 0;
err:
    abac_put_user_profile(user_profile);

    return -1;
}

int
ecall_abac_object_attribute_grant(char * path, char * attribute_name_IN, char * attribute_value_IN)
{
    // TODO
    return -1;
}

int
ecall_abac_object_attribute_revoke(char * path, char * attribute_name_IN)
{
    // TODO
    return -1;
}

int
ecall_abac_object_attribute_ls(char * path)
{
    // TODO
    return -1;
}
