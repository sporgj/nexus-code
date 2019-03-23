#include "abac_internal.h"

#include "../metadata.h"

static struct nexus_metadata * attribute_store_metadata = NULL;

static struct nexus_metadata * current_user_profile_metadata = NULL;

static struct abac_superinfo   global_abac_superinfo;


struct attribute_store *
abac_global_attribute_store()
{
    // TODO
    return NULL;
}

int
abac_global_export_macversion(struct mac_and_version * macversion)
{
    // TODO
    return -1;
}


static inline struct nexus_uuid *
__attribute_store_uuid()
{
    return &global_supernode->abac_superinfo.attribute_store_uuid;
}

static inline struct nexus_uuid *
__policy_store_uuid()
{
    return &global_supernode->abac_superinfo.policy_store_uuid;
}

static int
abac_acquire_attribute_store(nexus_io_flags_t flags)
{
    struct nexus_uuid * uuid = __attribute_store_uuid();

    bool has_changed;


    if (attribute_store_metadata == NULL) {
        attribute_store_metadata = nexus_metadata_load(uuid, NEXUS_ATTRIBUTE_STORE, flags);

        if (attribute_store_metadata == NULL) {
            log_error("nexus_metadata_load() FAILED\n");
            return NULL;
        }

        return attribute_store_metadata->attribute_store;
    }

    if (nexus_metadata_revalidate(attribute_store_metadata, flags, &has_changed)) {
        log_error("nexus_metadata_revalidate() FAILED\n");
        return NULL;
    }

    return attribute_store_metadata->attribute_store;
}

int
abac_flush_attribute_store()
{
    return nexus_metadata_store(attribute_store_metadata);
}

void
abac_release_attribute_store()
{
    nexus_metadata_unlock(attribute_store_metadata);
}

int
abac_runtime_mount()
{
    if (abac_acquire_attribute_store(NEXUS_FREAD) == NULL) {
        log_error("could not load attribute store\n");
        return -1;
    }

    return 0;
}

int
abac_runtime_create(struct abac_superinfo * dst_abac_superinfo)
{
    struct nexus_metadata * tmp_metadata = NULL;

    struct nexus_uuid * policy_store_uuid    = &dst_abac_superinfo->policy_store_uuid;
    struct nexus_uuid * attribute_store_uuid = &dst_abac_superinfo->attribute_store_uuid;


    nexus_uuid_gen(policy_store_uuid);
    nexus_uuid_gen(attribute_store_uuid);

    // TODO write the policy store

    // create the attribute store metadata
    {
        tmp_metadata = nexus_metadata_create(attribute_store_uuid, NEXUS_ATTRIBUTE_STORE);
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
