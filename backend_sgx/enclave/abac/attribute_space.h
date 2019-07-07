/**
 * Manages all the user-defined attributes
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include "abac_types.h"
#include "abac_internal.h"

struct attribute_space {
    struct nexus_uuid        my_uuid;
    struct nexus_uuid        root_uuid;

    size_t                   count;

    size_t                   last_serialized_size;

    struct nexus_mac         mac;

    struct hashmap           map_attribute_schemas; // lookup by uuid
    struct list_head         list_attribute_schemas;

    struct nexus_metadata  * metadata;
};


struct attribute_space *
attribute_space_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
attribute_space_free(struct attribute_space * attr_space);


const struct attribute_schema *
attribute_space_find_uuid(struct attribute_space * attr_space, struct nexus_uuid * uuid);

const struct attribute_schema *
attribute_space_find_name(struct attribute_space * attr_space, char * name);

void
attribute_space_export_macversion(struct attribute_space * attr_space,
                                  struct mac_and_version * macversion);

int
attribute_space_add(struct attribute_space * attr_space, char * name, attribute_type_t type);

int
attribute_space_del(struct attribute_space * attr_space, char * name);


struct attribute_space *
attribute_space_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

struct attribute_space *
attribute_space_load(struct nexus_uuid * uuid, nexus_io_flags_t flags);

int
attribute_space_store(struct attribute_space * attr_space, size_t version, struct nexus_mac * mac);

int
UNSAFE_attribute_space_export(struct attribute_space      * attr_space,
                              struct nxs_attribute_schema * attribute_schema_array_out,
                              size_t                        attribute_schema_array_capacity,
                              size_t                        offset,
                              size_t                      * total_count_out,
                              size_t                      * result_count_out);

