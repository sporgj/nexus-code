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

    struct nexus_mac                mac;

    struct attribute_table        * attribute_table;

    struct nexus_metadata         * metadata;
};



struct user_profile *
user_profile_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
user_profile_free(struct user_profile * user_profile);

struct user_profile *
user_profile_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

int
user_profile_store(struct user_profile * user_profile, uint32_t version, struct nexus_mac * mac);


int
user_profile_grant_attribute(struct user_profile * user_profile, char * name, char * value);

int
user_profile_revoke_attribute(struct user_profile * user_profile, char * name);

int
UNSAFE_user_profile_attribute_ls(struct user_profile       * user_profile,
                                 struct nxs_attribute_pair * attribute_pair_array,
                                 size_t                      attribute_pair_capacity,
                                 size_t                      offset,
                                 size_t                    * result_count,
                                 size_t                    * total_count);
