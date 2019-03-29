#include "policy_store.h"


struct __policy_store_hdr {
    struct nexus_uuid   my_uuid;
    struct nexus_uuid   root_uuid;

    uint32_t            rules_count;
} __attribute__((packed));



static void
policy_store_init(struct policy_store * policy_store)
{
    // TODO
}

struct policy_store *
policy_store_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid)
{
    struct policy_store * policy_store = nexus_malloc(sizeof(struct policy_store));

    nexus_uuid_copy(root_uuid, &policy_store->root_uuid);
    nexus_uuid_copy(my_uuid, &policy_store->my_uuid);

    policy_store_init(policy_store);

    return policy_store;
}

void
policy_store_destroy(struct policy_store * policy_store)
{
    nexus_list_destroy(&policy_store->rules_list);
    nexus_free(policy_store);
}


struct policy_store *
policy_store_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    // TODO
    return NULL;
}

int
policy_store_store(struct policy_store * policy_store, struct nexus_mac * mac)
{
    // TODO
    return -1;
}

struct policy_rule *
policy_store_add(struct policy_store * policy_store, char * policy_string)
{
    // TODO
    return NULL;
}

int
policy_store_del(struct nexus_uuid * rule_uuid)
{
    return -1;
}
