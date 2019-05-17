#include "../enclave_internal.h"

#include "../abac/attribute_store.h"
#include "../abac/policy_store.h"
#include "../abac/db.h"


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
ecall_abac_attribute_ls(struct nxs_attribute_schema * attribute_schema_array_out,
                        size_t                      attribute_schema_array_capacity,
                        size_t                      offset,
                        size_t                    * total_count_out,
                        size_t                    * result_count_out)
{

    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FRDWR);

    if (attribute_store == NULL) {
        log_error("abac_acquire_attribute_store() FAILED\n");
        return -1;
    }

    if (UNSAFE_attribute_store_export(attribute_store,
                                      attribute_schema_array_out,
                                      attribute_schema_array_capacity,
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
                             struct nxs_attribute_pair * attribute_pair_array_out,
                             size_t                      attribute_pair_capacity,
                             size_t                      offset,
                             size_t                    * result_count_out,
                             size_t                    * total_count_out)
{
    struct user_profile * user_profile = abac_get_user_profile(username_IN, NEXUS_FREAD);

    if (user_profile == NULL) {
        log_error("abac_get_user_profile() FAILED\n");
        return -1;
    }

    if (UNSAFE_user_profile_attribute_ls(user_profile,
                                         attribute_pair_array_out,
                                         attribute_pair_capacity,
                                         offset,
                                         result_count_out,
                                         total_count_out)) {
        log_error("UNSAFE_user_profile_attribute_ls FAILED\n");
        goto err;
    }

    abac_put_user_profile(user_profile);

    return 0;
err:
    abac_put_user_profile(user_profile);

    return -1;
}

static int
__do_object_attribute_grant(struct nexus_metadata * metadata, char * name, char * value)
{
    struct attribute_table * attribute_table = NULL;
    struct attribute_schema  * attribute_schema  = NULL;
    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);

    if (attribute_store == NULL) {
        log_error("could not get global attribute store\n");
        return -1;
    }

    attribute_schema = (struct attribute_schema *)attribute_store_find_name(attribute_store, name);

    if (attribute_schema == NULL) {
        log_error("could not find object attribute (%s) in store\n", name);
        return -1;
    }

    if (attribute_schema->type != OBJECT_ATTRIBUTE_TYPE) {
        log_error("incorrect attribute type for (%s)\n", attribute_schema->name);
        return -1;
    }

    if (metadata->type == NEXUS_FILENODE) {
        attribute_table = metadata->filenode->attribute_table;
    } else if (metadata->type == NEXUS_DIRNODE) {
        attribute_table = metadata->dirnode->attribute_table;
    } else {
        log_error("incorrect metadata type\n");
        return -1;
    }

    if (attribute_table_add(attribute_table, &attribute_schema->uuid, value)) {
        log_error("attribute_table_add() FAILED\n");
        return -1;
    }

    __metadata_set_dirty(metadata);

    return 0;
}

int
ecall_abac_object_attribute_grant(char * path_IN,
                                  char * attribute_name_IN,
                                  char * attribute_value_IN)
{
    struct nexus_metadata * metadata = NULL;

    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(path_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    if (__do_object_attribute_grant(metadata, attribute_name_IN, attribute_value_IN)) {
        log_error("__do_object_attribute_grant() FAILED\n");
        goto out_err;
    }

    if (nexus_metadata_store(metadata)) {
        log_error("flushing metadata failed\n");
        goto out_err;
    }

    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return 0;
out_err:
    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return -1;
}

static int
__do_object_attribute_revoke(struct nexus_metadata * metadata, char * name)
{
    struct attribute_table * attribute_table = NULL;
    struct attribute_schema  * attribute_schema  = NULL;
    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);

    if (attribute_store == NULL) {
        log_error("could not get global attribute store\n");
        return -1;
    }

    attribute_schema = (struct attribute_schema *)attribute_store_find_name(attribute_store, name);

    if (attribute_schema == NULL) {
        log_error("could not find object attribute (%s) in store\n", name);
        return -1;
    }

    if (attribute_schema->type != OBJECT_ATTRIBUTE_TYPE) {
        log_error("incorrect attribute type for (%s)\n", attribute_schema->name);
        return -1;
    }

    if (metadata->type == NEXUS_FILENODE) {
        attribute_table = metadata->filenode->attribute_table;
    } else if (metadata->type == NEXUS_DIRNODE) {
        attribute_table = metadata->dirnode->attribute_table;
    } else {
        log_error("incorrect metadata type\n");
        return -1;
    }

    if (attribute_table_del(attribute_table, &attribute_schema->uuid)) {
        log_error("attribute_table_del() FAILED\n");
        return -1;
    }

    __metadata_set_dirty(metadata);

    return 0;
}

int
ecall_abac_object_attribute_revoke(char * path_IN, char * attribute_name_IN)
{
    struct nexus_metadata * metadata = NULL;

    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(path_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    if (__do_object_attribute_revoke(metadata, attribute_name_IN)) {
        log_error("__do_object_attribute_revoke() FAILED\n");
        goto out_err;
    }

    if (nexus_metadata_store(metadata)) {
        log_error("flushing metadata failed\n");
        goto out_err;
    }

    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return 0;
out_err:
    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return -1;
}

static inline int
__do_object_attribute_ls(struct nexus_metadata     * metadata,
                         struct nxs_attribute_pair * attribute_pair_array,
                         size_t                      attribute_pair_capacity,
                         size_t                      offset,
                         size_t                    * result_count,
                         size_t                    * total_count)
{
    struct attribute_table * attribute_table = NULL;
    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);

    if (attribute_store == NULL) {
        log_error("could not get attribute_store\n");
        return -1;
    }

    if (metadata->type == NEXUS_FILENODE) {
        attribute_table = metadata->filenode->attribute_table;
    } else if (metadata->type == NEXUS_DIRNODE) {
        attribute_table = metadata->dirnode->attribute_table;
    } else {
        log_error("incorrect metadata type\n");
        return -1;
    }

    return  UNSAFE_attribute_table_ls(attribute_table,
                                      attribute_store,
                                      attribute_pair_array,
                                      attribute_pair_capacity,
                                      offset,
                                      result_count,
                                      total_count);
}

int
ecall_abac_object_attribute_ls(char                      * path_IN,
                               struct nxs_attribute_pair * attribute_pair_array_out,
                               size_t                      attribute_pair_array_capacity,
                               size_t                      offset,
                               size_t                    * total_count_out,
                               size_t                    * result_count_out)
{
    struct nexus_metadata * metadata = NULL;

    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(path_IN, NEXUS_FREAD);

    if (metadata == NULL) {
        log_error("could not get metadata\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    if (__do_object_attribute_ls(metadata,
                                 attribute_pair_array_out,
                                 attribute_pair_array_capacity,
                                 offset,
                                 total_count_out,
                                 result_count_out)) {
        log_error("__do_object_attribute_revoke() FAILED\n");
        goto out_err;
    }

    if (nexus_metadata_store(metadata)) {
        log_error("flushing metadata failed\n");
        goto out_err;
    }

    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return 0;
out_err:
    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return -1;
}


int
ecall_abac_policy_add(char * policy_string_IN, struct nexus_uuid * uuid_out)
{
    struct policy_store * policy_store = NULL;
    struct policy_rule  * policy_rule  = parse_abac_policy(policy_string_IN);

    if (policy_rule == NULL) {
        log_error("could not parse policy rule\n");
        return -1;
    }

    policy_store = abac_acquire_policy_store(NEXUS_FRDWR);

    if (policy_store == NULL) {
        policy_rule_free(policy_rule);
        log_error("abac_acquire_policy_store() FAILED\n");
        return -1;
    }

    if (policy_store_add(policy_store, policy_rule)) {
        log_error("policy_store_add() FAILED\n");
        goto out_err;
    }

    if (abac_flush_policy_store()) {
        log_error("abac_flush_policy_store() FAILED\n");
        goto out_err;
    }

    nexus_uuid_copy(&policy_rule->rule_uuid, uuid_out);

    return 0;

out_err:
    if (policy_rule) {
        policy_rule_free(policy_rule);
    }

    abac_release_policy_store();

    return -1;
}

int
ecall_abac_policy_del(struct nexus_uuid * rule_uuid_IN)
{
    struct policy_store * policy_store = abac_acquire_policy_store(NEXUS_FRDWR);

    if (policy_store == NULL) {
        log_error("could not acquire policy store\n");
        return -1;
    }

    if (policy_store_del(policy_store, rule_uuid_IN)) {
        log_error("policy_store_del() FAILED\n");
        goto out_err;
    }

    if (abac_flush_policy_store()) {
        log_error("abac_flush_policy_store() FAILED\n");
        goto out_err;
    }

    return 0;
out_err:
    abac_release_policy_store();

    return -1;
}

int
ecall_abac_policy_ls(struct nxs_policy_rule * rules_buffer_out,
                     size_t                   rules_buffer_capacity,
                     size_t                   offset,
                     size_t                 * total_count_out,
                     size_t                 * result_count_out)
{
    struct policy_store * policy_store = abac_acquire_policy_store(NEXUS_FREAD);

    if (policy_store == NULL) {
        log_error("could not acquire policy store\n");
        return -1;
    }

    if (policy_store_ls(policy_store,
                        rules_buffer_out,
                        rules_buffer_capacity,
                        offset,
                        total_count_out,
                        result_count_out)) {
        log_error("policy_store_ls() FAILED\n");
        goto out_err;
    }

    return 0;
out_err:
    abac_release_policy_store();

    return -1;
}


int
ecall_abac_print_facts()
{
    return UNSAFE_db_print_facts();
}

int
ecall_abac_print_rules()
{
    return UNSAFE_bouncer_print_rules();
}
