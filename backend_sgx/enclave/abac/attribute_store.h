/**
 * Manages all the user-defined attributes
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include "abac_types.h"
#include "abac_internal.h"

struct attribute_store {
    struct nexus_uuid        my_uuid;
    struct nexus_uuid        root_uuid;

    size_t                   count;

    struct nexus_mac         mac;

    struct list_head         list_attribute_schemas;

    struct nexus_metadata  * metadata;
};


struct attribute_store *
attribute_store_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
attribute_store_free(struct attribute_store * attr_store);


const struct attribute_schema *
attribute_store_find_uuid(struct attribute_store * attr_store, struct nexus_uuid * uuid);

const struct attribute_schema *
attribute_store_find_name(struct attribute_store * attr_store, char * name);

void
attribute_store_export_macversion(struct attribute_store * attr_store,
                                  struct mac_and_version * macversion);

int
attribute_store_add(struct attribute_store * attr_store, char * name, attribute_type_t type);

int
attribute_store_del(struct attribute_store * attr_store, char * name);


struct attribute_store *
attribute_store_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

struct attribute_store *
attribute_store_load(struct nexus_uuid * uuid, nexus_io_flags_t flags);

int
attribute_store_store(struct attribute_store * attr_store, size_t version, struct nexus_mac * mac);

int
UNSAFE_attribute_store_export(struct attribute_store      * attr_store,
                              struct nxs_attribute_schema * attribute_schema_array_out,
                              size_t                        attribute_schema_array_capacity,
                              size_t                        offset,
                              size_t                      * total_count_out,
                              size_t                      * result_count_out);

