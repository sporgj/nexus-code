#include "abac_internal.h"


struct policy_store {
    struct nexus_uuid       my_uuid;

    uint32_t                rules_count;

    struct nexus_list       rules_list;
};


struct policy_store *
policy_store_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
policy_store_destroy(struct policy_store * policy_store);



/// adds a policy to the store and returns the created policy rule
struct policy_rule *
policy_store_add_policy(struct policy_store * policy_store, char * policy_string);

void
policy_store_delete_policy(struct nexus_uuid * rule_uuid);
