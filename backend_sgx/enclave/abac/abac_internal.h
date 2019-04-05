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


// returns the global usertable
struct nexus_usertable *
abac_global_get_usertable(nexus_io_flags_t flags);

int
abac_global_put_usertable(struct nexus_usertable * usertable);
