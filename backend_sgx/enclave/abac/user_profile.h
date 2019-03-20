/**
 * Stores attribute information about a particular user
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include "abac_internal.h"


struct user_profile {
    struct nexus_uuid               my_uuid;
    struct nexus_uuid               root_uuid;

    size_t                          attribute_count;

    struct mac_and_version          attribute_store_macversion;

    struct nexus_mac                mac;

    struct attribute_table        * attribute_table;

    struct nexus_metadata         * metadata;
};



struct user_profile *
user_profile_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
user_profile_free(struct user_profile * user_profile);

struct user_profile *
user_profile_load(struct nexus_uuid * uuid, nexus_io_flags_t flags);

struct user_profile *
user_profile_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

int
user_profile_store(struct user_profile * user_profile, uint32_t version, struct nexus_mac * mac);


int
user_profile_grant_attribute(struct user_profile * user_profile, char * name, char * value);

int
user_profile_revoke_attribute(struct user_profile * user_profile, char * name);
