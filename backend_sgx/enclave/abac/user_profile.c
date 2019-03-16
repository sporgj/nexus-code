#include "user_profile.h"


struct __user_profile_hdr {
    size_t                          attribute_count;

    mac_and_version_t               attribute_store_macversion;
} __attribute__((packed));


// -- creating/destroying
struct user_profile *
attribute_store_create(struct nexus_uuid * uuid, struct nexus_uuid * root_uuid)
{
    struct user_profile * user_profile = nexus_malloc(sizeof(struct user_profile));

    nexus_uuid_copy(uuid, &attribute_store->my_uuid);
    nexus_uuid_copy(root_uuid, &attribute_store->root_uuid);

    return user_profile;
}

void
attribute_store_destroy(struct user_profile * user_profile)
{
    attribute_table_destroy(user_profile->attribute_table);
    nexus_free(user_profile);
}


int
user_profile_grant_attribute(struct user_profile * user_profile, char * name, char * value)
{

}

int
user_profile_revoke_attribute(struct user_profile * user_profile, char * name)
{

}



