#include "abac_internal.h"

#include "../vfs.h"
#include "../metadata.h"

#include "../enclave_internal.h"


static struct nexus_metadata * attribute_space_metadata = NULL;
static struct nexus_metadata * policy_store_metadata    = NULL;

static struct nexus_metadata * current_userprofile_metadata = NULL;


int
abac_global_export_macversion(struct mac_and_version * macversion)
{
    struct attribute_space * attribute_space = abac_acquire_attribute_space(NEXUS_FREAD);

    if (attribute_space == NULL) {
        log_error("could not get attribute store\n");
        return -1;
    }

    nexus_metadata_export_mac(attribute_space->metadata, &macversion->mac);
    macversion->version = attribute_space->metadata->version;

    return 0;
}


struct nexus_uuid *
abac_attribute_space_uuid()
{
    return &global_supernode->abac_superinfo.attribute_space_uuid;
}

struct nexus_uuid *
abac_policy_store_uuid()
{
    return &global_supernode->abac_superinfo.policy_store_uuid;
}

struct attribute_space *
abac_acquire_attribute_space(nexus_io_flags_t flags)
{
    struct nexus_uuid * uuid = abac_attribute_space_uuid();

    bool has_changed;


    if (attribute_space_metadata == NULL) {
        attribute_space_metadata = nexus_metadata_load(uuid, NEXUS_ATTRIBUTE_STORE, flags);

        if (attribute_space_metadata == NULL) {
            log_error("nexus_metadata_load() FAILED\n");
            return NULL;
        }

        return attribute_space_metadata->attribute_space;
    }

    if (nexus_metadata_revalidate(attribute_space_metadata, flags, &has_changed)) {
        log_error("nexus_metadata_revalidate() FAILED\n");
        return NULL;
    }

    return attribute_space_metadata->attribute_space;
}

int
abac_flush_attribute_space()
{
    return nexus_metadata_store(attribute_space_metadata);
}

void
abac_release_attribute_space()
{
    nexus_metadata_unlock(attribute_space_metadata);
}

struct policy_store *
abac_refresh_bouncer_policy_store()
{
    struct nexus_uuid * uuid = abac_policy_store_uuid();

    struct nexus_metadata * old_metadata = policy_store_metadata;
    struct nexus_metadata * new_metadata = NULL;

    if (old_metadata && !nexus_metadata_has_changed(old_metadata)) {
        if (bouncer_update_policy_store(NULL, old_metadata->policy_store)) {
            log_error("bouncer_update_policy_store() FAILED\n");
            return NULL;
        }

        return policy_store_metadata->policy_store;
    }

    new_metadata = nexus_metadata_load(uuid, NEXUS_POLICY_STORE, NEXUS_FREAD);

    if (new_metadata == NULL) {
        log_error("nexus_metadata_load() FAILED\n");
        return NULL;
    }

    if (bouncer_update_policy_store(old_metadata->policy_store, new_metadata->policy_store)) {
        nexus_metadata_free(new_metadata);
        log_error("bouncer_update_policy_store() FAILED\n");
        return NULL;
    }

    nexus_metadata_free(old_metadata);

    policy_store_metadata = new_metadata;

    return policy_store_metadata->policy_store;
}

struct policy_store *
abac_acquire_policy_store(nexus_io_flags_t flags)
{
    struct nexus_uuid * uuid = abac_policy_store_uuid();

    bool has_changed;


    if (policy_store_metadata == NULL) {
        policy_store_metadata = nexus_metadata_load(uuid, NEXUS_POLICY_STORE, flags);

        if (policy_store_metadata == NULL) {
            log_error("nexus_metadata_load() FAILED\n");
            return NULL;
        }

        return policy_store_metadata->policy_store;
    }

    if (nexus_metadata_revalidate(policy_store_metadata, flags, &has_changed)) {
        log_error("nexus_metadata_revalidate() FAILED\n");
        return NULL;
    }

    return policy_store_metadata->policy_store;
}

int
abac_flush_policy_store()
{
    return nexus_metadata_store(policy_store_metadata);
}

void
abac_release_policy_store()
{
    nexus_metadata_unlock(policy_store_metadata);
}

int
abac_runtime_mount()
{
    if (abac_acquire_attribute_space(NEXUS_FREAD) == NULL) {
        log_error("could not load attribute store\n");
        return -1;
    }

    if (abac_acquire_policy_store(NEXUS_FREAD) == NULL) {
        log_error("could not load policy store\n");
        return -1;
    }

    if (bouncer_init()) {
        log_error("bouncer_init() FAILED\n");
        return -1;
    }

    return 0;
}

int
abac_runtime_create(struct abac_superinfo * dst_abac_superinfo)
{
    struct nexus_metadata * tmp_metadata = NULL;

    struct nexus_uuid * policy_store_uuid    = &dst_abac_superinfo->policy_store_uuid;
    struct nexus_uuid * attribute_space_uuid = &dst_abac_superinfo->attribute_space_uuid;


    nexus_uuid_gen(policy_store_uuid);
    nexus_uuid_gen(attribute_space_uuid);

    // create the attribute store metadata
    {
        tmp_metadata = nexus_metadata_create(attribute_space_uuid, NEXUS_ATTRIBUTE_STORE);
        if (tmp_metadata == NULL) {
            log_error("nexus_metadata_create() FAILED\n");
            goto out_err;
        }

        if (nexus_metadata_store(tmp_metadata)) {
            nexus_metadata_free(tmp_metadata);
            log_error("nexus_metadata_store() FAILED\n");
            goto out_err;
        }

        nexus_metadata_free(tmp_metadata);
    }

    // create the policy store
    {
        tmp_metadata = nexus_metadata_create(policy_store_uuid, NEXUS_POLICY_STORE);
        if (tmp_metadata == NULL) {
            log_error("nexus_metadata_create() FAILED\n");
            goto out_err;
        }

        if (nexus_metadata_store(tmp_metadata)) {
            nexus_metadata_free(tmp_metadata);
            log_error("nexus_metadata_store() FAILED\n");
            goto out_err;
        }

        nexus_metadata_free(tmp_metadata);
    }

    return 0;
out_err:
    return -1;
}

void
abac_runtime_destroy()
{
    // TODO
}

attribute_type_t
attribute_type_from_str(char * attribute_type_str)
{
    if (strncmp("user", attribute_type_str, 5) == 0) {
        return USER_ATTRIBUTE_TYPE;
    } else if (strncmp("object", attribute_type_str, 6) == 0) {
        return OBJECT_ATTRIBUTE_TYPE;
    }

    return -1;
}

int
attribute_type_to_str(attribute_type_t attribute_type, char * buffer_out, size_t buflen)
{
    char * attr_str = NULL;

    switch(attribute_type) {
    case USER_ATTRIBUTE_TYPE:
        attr_str = "user";
        break;
    case OBJECT_ATTRIBUTE_TYPE:
        attr_str = "object";
        break;
    default:
        log_error("could not find attribute_type from argument\n");
        return -1;
    }

    strncpy(buffer_out, attr_str, buflen);

    return 0;
}


// TODO have cache interface for user_profiles

struct user_profile *
abac_get_user_profile(char * username, nexus_io_flags_t flags)
{
    struct nexus_metadata  * user_profile_metadata = NULL;

    struct nexus_user      * rst_user    = NULL;
    struct nexus_usertable * usertable   = nexus_vfs_acquire_user_table(NEXUS_FREAD);

    if (usertable == NULL) {
        log_error("nexus_global_get_usertable() FAILED\n");
        return NULL;
    }

    rst_user = nexus_usertable_find_name(usertable, username);

    if (rst_user == NULL) {
        log_error("could not find user (%s)\n", username);
        goto err;
    }

    // now load the user profile using the uuid
    user_profile_metadata = nexus_metadata_load(&rst_user->user_uuid, NEXUS_USER_PROFILE, flags);

    if (user_profile_metadata == NULL) {
        log_error("could not load user profile metadata\n");
        goto err;
    }

    nexus_vfs_release_user_table();

    return user_profile_metadata->user_profile;
err:
    nexus_vfs_release_user_table();

    return NULL;
}

int
abac_put_user_profile(struct user_profile * user_profile)
{
    if (nexus_metadata_store(user_profile->metadata)) {
        log_error("nexus_metadata_store() FAILED\n");
        return -1;
    }

    nexus_metadata_unlock(user_profile->metadata);

    nexus_metadata_free(user_profile->metadata);

    return 0;
}

int
abac_create_user_profile(struct nexus_uuid * user_uuid)
{
    struct nexus_metadata * tmp_metadata = NULL;

    tmp_metadata = nexus_metadata_create(user_uuid, NEXUS_USER_PROFILE);
    if (tmp_metadata == NULL) {
        log_error("nexus_metadata_create() FAILED\n");
        goto out_err;
    }

    if (nexus_metadata_store(tmp_metadata)) {
        log_error("nexus_metadata_store() FAILED\n");
        goto out_err;
    }

    nexus_metadata_free(tmp_metadata);
    return 0;
out_err:
    nexus_metadata_free(tmp_metadata);
    return -1;
}

int
abac_del_user_profile(struct nexus_uuid * user_uuid)
{
    return buffer_layer_delete(user_uuid);
}


struct user_profile *
abac_acquire_current_user_profile(nexus_io_flags_t flags)
{
    bool has_changed;

    if (nexus_enclave_is_current_user_owner()) {
        return NULL;
    }

    struct nexus_uuid * uuid = &global_user_struct->user_uuid;

    if (current_userprofile_metadata == NULL) {
        current_userprofile_metadata = nexus_metadata_load(uuid, NEXUS_USER_PROFILE, flags);

        if (current_userprofile_metadata == NULL) {
            log_error("nexus_metadata_load() FAILED\n");
            return NULL;
        }

        return current_userprofile_metadata->user_profile;
    }

    if (nexus_metadata_revalidate(current_userprofile_metadata, flags, &has_changed)) {
        log_error("nexus_metadata_revalidate() FAILED\n");
        return NULL;
    }

    return current_userprofile_metadata->user_profile;

    return NULL;
}

void
abac_release_current_user_profile()
{
    nexus_metadata_unlock(current_userprofile_metadata);
}


void
abac_export_telemetry(struct nxs_telemetry * telemetry)
{
    struct attribute_space * attribute_space = NULL;
    struct policy_store    * policy_store    = NULL;
    struct nexus_usertable * global_usertable = NULL;
    struct user_profile    * user_profile = NULL;

    db_export_telemetry(telemetry);

    telemetry->attribute_space_bytes = 0;
    telemetry->policy_store_bytes = 0;

    attribute_space = abac_acquire_attribute_space(NEXUS_FREAD);

    if (attribute_space) {
        telemetry->attribute_space_bytes = attribute_space->last_serialized_size;
        telemetry->attribute_space_count = attribute_space->count;
        abac_release_attribute_space();
    } else {
        log_error("could not acquire attribute_space for telemetry\n");
    }

    policy_store = abac_acquire_policy_store(NEXUS_FREAD);

    if (policy_store) {
        telemetry->policy_store_bytes = policy_store->last_serialized_size;
        telemetry->policy_store_count = policy_store->rules_count;
        abac_release_policy_store();
    } else {
        log_error("could not acquire policy_store for telemetry\n");
    }

    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FREAD);

    if (global_usertable) {
        telemetry->user_table_bytes = nexus_usertable_buflen(global_usertable);
        telemetry->user_table_count = global_usertable->user_count;
        nexus_vfs_release_user_table();
    } else {
        log_error("could not acquire glocal user table\n");
    }

    user_profile = abac_acquire_current_user_profile(NEXUS_FREAD);

    if (user_profile) {
        telemetry->user_profile_bytes = user_profile_get_size(user_profile);
        telemetry->user_profile_count = user_profile->attribute_table->count;

        abac_release_current_user_profile();
    }
}
