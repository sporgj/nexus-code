#include "user_profile.h"


struct __user_profile_hdr {
    size_t                          attribute_count;

    mac_and_version_t               attribute_store_macversion;
} __attribute__((packed));



static void
__user_profile_set_dirty(struct user_profile * user_profile)
{
    if (user_profile->metadata) {
        __metadata_set_dirty(user_profile->metadata);
    }
}


struct user_profile *
user_profile_create(struct nexus_uuid * uuid, struct nexus_uuid * root_uuid)
{
    struct user_profile * user_profile = nexus_malloc(sizeof(struct user_profile));

    user_profile->attribute_table = attribute_table_create();

    nexus_uuid_copy(root_uuid, &user_profile->root_uuid);
    nexus_uuid_copy(uuid, &user_profile->my_uuid);

    return user_profile;
}

void
user_profile_destroy(struct user_profile * user_profile)
{
    if (user_profile->attribute_table) {
        attribute_table_free(user_profile->attribute_table);
    }

    nexus_free(user_profile);
}



/// -- load/store

static size_t
__get_user_profile_size(struct user_profile * user_profile)
{
    return (sizeof(struct __user_profile_hdr) + attribute_table_get_size(user_profile->
}

int
user_profile_store(struct user_profile * user_profile)
{
    struct nexus_crypto_buf * crypto_buffer     = NULL;
}

//// load/store


int
user_profile_grant_attribute(struct user_profile * user_profile, char * name, char * value)
{
    struct attribute_term * attribute_term = NULL;

    struct attribute_store * attribute_store = abac_global_attribute_store();

    if (attribute_store == NULL) {
        log_error("could not get global attribute store\n");
        return -1;
    }

    attribute_term = (struct attribute_term *)attribute_store_find_name(name);

    if (attribute_term == NULL) {
        log_error("could not find attribute (%s) in store\n", name);
        return -1;
    }

    if (attribute_table_add(user_profile->attribute_table, &attribute_term->uuid, value)) {
        log_error("attribute_table_add() FAILED\n");
        return -1;
    }

    __user_profile_set_dirty(user_profile);

    return 0;
}

int
user_profile_revoke_attribute(struct user_profile * user_profile, char * name)
{
    struct attribute_term * attribute_term = NULL;

    struct attribute_store * attribute_store = abac_global_attribute_store();

    if (attribute_store == NULL) {
        log_error("could not get global attribute store\n");
        return -1;
    }

    attribute_term = (struct attribute_term *)attribute_store_find_name(name);

    if (attribute_term == NULL) {
        log_error("could not find attribute (%s) in store\n", name);
        return -1;
    }

    if (attribute_table_del(user_profile->attribute_table, &attribute_term->uuid)) {
        log_error("attribute_table_del() FAILED\n");
        return -1;
    }

    __user_profile_set_dirty(user_profile);

    return 0;
}



