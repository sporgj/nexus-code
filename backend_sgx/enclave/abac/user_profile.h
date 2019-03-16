/**
 * Stores attribute information about a particular user
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include "abac_internal.h"


struct user_profile {
    size_t                          attribute_count;

    mac_and_version_t               attribute_store_macversion;

    struct nexus_mac                mac;

    struct attribute_table        * attribute_table;

    struct nexus_metadata         * metadata;
};



struct user_profile *
user_profile_create(struct nexus_uuid * uuid, struct nexus_uuid * root_uuid);

void
user_profile_destroy(struct user_profile * user_profile);


int
user_profile_grant_attribute(struct user_profile * user_profile, char * name, char * value);

int
user_profile_revoke_attribute(struct user_profile * user_profile, char * name);
