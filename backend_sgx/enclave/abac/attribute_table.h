/**
 * The attribute table stores the respective
 *
 * @author Judicael Briand <jbriand@cs.pitt.edu>
 */

#pragma once

#include <stdint.h>

#include "abac_internal.h"
#include "abac_types.h"

#include <libnexus_trusted/rapidstring.h>


struct attribute_space;

struct attribute_table {
    struct nexus_uuid       uuid;
    size_t                  count;

    struct nexus_uuid       audit_log_uuid;

    size_t                  generation;

    struct mac_and_version  attribute_space_macversion;

    struct hashmap          attribute_map;
};

struct attribute_entry {
    struct hashmap_entry    hash_entry;

    struct nexus_uuid       attr_uuid;
    size_t                  attr_val_len;
    char                    attr_val[ATTRIBUTE_VALUE_SIZE];
};


struct attribute_table *
attribute_table_from_buffer(uint8_t * buffer, size_t buflen);

struct attribute_table *
attribute_table_create();

void
attribute_table_free(struct attribute_table * attribute_table);

bool
attribute_table_has_audit_log(struct attribute_table * attribute_table);

void
attribute_table_set_audit_log(struct attribute_table * attribute_table, struct nexus_uuid * uuid);

int
attribute_table_get_audit_log(struct attribute_table * attribute_table, struct nexus_uuid * uuid);


size_t
attribute_table_get_size(struct attribute_table * attribute_table);

int
attribute_table_store(struct attribute_table * attribute_table, uint8_t * buffer, size_t buflen);


int
attribute_table_add(struct attribute_table * attribute_table, struct nexus_uuid * uuid, char * value);

int
attribute_table_del(struct attribute_table * attribute_table, struct nexus_uuid * uuid);

const char *
attribute_table_find(struct attribute_table * attribute_table, struct nexus_uuid * uuid);

/// exports all the attribute pairs as datalog facts
int
attribute_table_export_facts(struct attribute_table * attribute_table,
                             struct attribute_space * attribute_space,
                             char                   * first_term,
                             rapidstring            * string_builder,
                             size_t                 * p_skip_count);

int
attribute_table_export_to_datalog_db(struct attribute_table * attribute_table,
                                     struct attribute_space * attribute_space,
                                     struct nexus_uuid      * object_uuid,
                                     rapidstring            * string_builder,
                                     size_t                 * p_skip_count);


// writes all the attribute pairs stored in the table
int
UNSAFE_attribute_table_ls(struct attribute_table    * attribute_table,
                          struct attribute_space    * attribute_space,
                          struct nxs_attribute_pair * attribute_pair_array,
                          size_t                      attribute_pair_capacity,
                          size_t                      offset,
                          size_t                    * result_count,
                          size_t                    * total_count);
