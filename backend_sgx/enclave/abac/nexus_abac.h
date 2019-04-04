#pragma once


#include "attribute_store.h"
#include "policy_store.h"
#include "policy_rule.h"
#include "user_profile.h"


/// exports

struct abac_superinfo {
    struct nexus_uuid policy_store_uuid;
    struct nexus_uuid attribute_store_uuid;
} __attribute__((packed));


/**
 * Called at volume mount. Reads the attribute_store and user_profile from
 * the backend.
 */
int
abac_runtime_mount();

void
abac_runtime_destroy();

/**
 * Initializes the abac runtime files.
 */
int
abac_runtime_create();



// get/put for user profiles

struct user_profile *
abac_get_user_profile(char * username, nexus_io_flags_t flags);

int
abac_put_user_profile(struct user_profile * user_profile);

int
abac_create_user_profile(struct nexus_uuid * user_uuid);

int
abac_del_user_profile(struct nexus_uuid * user_uuid);



// parser/lexer

struct policy_rule *
parse_abac_policy(char * policy_string);
