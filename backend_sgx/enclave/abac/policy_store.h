#include "abac_internal.h"


struct policy_store {
    struct nexus_uuid       my_uuid;
    struct nexus_uuid       root_uuid;

    uint32_t                rules_count;

    struct nexus_mac        mac;

    struct mac_and_version  attribute_store_macversion;

    struct nexus_list       rules_list;


    struct nexus_metadata * metadata;
};


struct policy_store *
policy_store_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
policy_store_free(struct policy_store * policy_store);


struct policy_store *
policy_store_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

int
policy_store_store(struct policy_store * policy_store, uint32_t version, struct nexus_mac * mac);



/// adds a policy to the store and returns the created policy rule
int
policy_store_add(struct policy_store * policy_store, struct policy_rule * policy_rule);

/// tries to delete a policy, returns -1 on FAILURE
int
policy_store_del(struct policy_store * policy_store, struct nexus_uuid * rule_uuid);


/**
 * Returns a list of policies matching the given action
 */
struct nexus_list *
policy_store_filter_by_action(struct policy_store * policy_store);



/* policy rule stuff */

struct policy_rule *
policy_rule_new(perm_type_t permission);

void
policy_rule_free(struct policy_rule * rule);

char *
policy_rule_to_str(struct policy_rule * rule);

int
policy_rule_push_atom(struct policy_rule * policy_rule, struct policy_atom * atom);

size_t
policy_rule_buf_size(struct policy_rule * rule);

uint8_t *
policy_rule_to_buf(struct policy_rule * rule, uint8_t * buffer, size_t buflen);

struct policy_rule *
policy_rule_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_dest_ptr);



/* policy atom */

struct policy_atom *
policy_atom_new(atom_type_t atom_type, pred_type_t pred_type);

void
policy_atom_free(struct policy_atom * atom);

size_t
policy_atom_buf_size(struct policy_atom * atom);

char *
policy_atom_to_str(struct policy_atom * atom);

int
policy_atom_push_arg(struct policy_atom * atom, char * str);

