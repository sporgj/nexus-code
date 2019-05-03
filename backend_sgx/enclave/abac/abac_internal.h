#pragma once

#include "../libnexus_trusted/nexus_log.h"
#include "../libnexus_trusted/nexus_uuid.h"
#include "../libnexus_trusted/nexus_util.h"
#include "../libnexus_trusted/nexus_mac.h"
#include "../libnexus_trusted/hashmap.h"

#include "../crypto_buffer.h"
#include "../metadata.h"

#include "abac_types.h"

extern struct nexus_supernode * global_supernode;
extern struct nexus_metadata  * global_supernode_metadata;

int
abac_global_export_macversion(struct mac_and_version * macversion);

struct nexus_uuid *
abac_attribute_store_uuid();

struct nexus_uuid *
abac_policy_store_uuid();


// utils for converting attribute_type
int
attribute_type_to_str(attribute_type_t attribute_type, char * buffer_out, size_t buflen);

/** return -1 on FAILURE */
attribute_type_t
attribute_type_from_str(char * attribute_type_str);


// attribute-store meteadata management

struct attribute_store *
abac_acquire_attribute_store(nexus_io_flags_t flags);

int
abac_flush_attribute_store();

void
abac_release_attribute_store();


// policy store

struct policy_store *
abac_acquire_policy_store(nexus_io_flags_t flags);

int
abac_flush_policy_store();

void
abac_release_policy_store();

struct policy_store *
abac_refresh_bouncer_policy_store();


// returns the global usertable
struct nexus_usertable *
abac_global_get_usertable(nexus_io_flags_t flags);

int
abac_global_put_usertable(struct nexus_usertable * usertable);


struct user_profile *
abac_acquire_current_user_profile(nexus_io_flags_t flags);

void
abac_release_current_user_profile();


// defined inside datalog-engine/interp.c
extern int
datalog_evaluate(char * datalog_buffer_IN, char ** string_ans);


int
bouncer_update_policy_store(struct policy_store * old_policystore,
                            struct policy_store * new_policystore);
