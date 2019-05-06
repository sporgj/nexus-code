#pragma once

#include "abac_types.h"

#include <libnexus_trusted/nexus_uuid.h>
#include <libnexus_trusted/hashmap.h>
#include <libnexus_trusted/list.h>

struct kb_fact;
struct nexus_metadata;

struct policy_rule;


// correspond to a particular user_profile, metadata or policy_store
struct kb_entity {
    struct nexus_uuid       uuid;
    char                  * uuid_str;

    attribute_type_t        attr_type; // denotes whether _isUser/_isObject have been added
    const struct kb_fact  * type_fact; // will be stored in the db

    struct hashmap          uuid_facts; // facts indexed by uuid (rules and attributes)
    struct hashmap          name_facts;  // facts indexed by name (sys functions)

    size_t                  uuid_facts_count;
    size_t                  name_facts_count;

    bool                    is_fully_asserted;

    size_t                  attribute_table_generation;
    size_t                  metadata_version;

    struct list_head        uuid_facts_lru;
};

struct kb_fact {
    struct hashmap_entry hash_entry;
    struct nexus_uuid    uuid;
    char                 name[ATTRIBUTE_NAME_MAX];

    char               * value;

    bool                 is_rule;
    struct policy_rule * rule_ptr;

    // whether it is in the db
    bool                 is_inserted;
    bool                 is_uuid_fact;

    struct kb_entity   * entity;

    size_t               generation;  // could also be a version

    struct list_head     db_list;
    struct list_head     entity_lru;   // all the assert facts will be towards the head
};


struct kb_entity *
kb_entity_new(struct nexus_uuid * uuid, attribute_type_t attribute_type);

void
kb_entity_free(struct kb_entity * entity);

struct kb_fact *
kb_entity_put_uuid_fact(struct kb_entity  * entity,
                        struct nexus_uuid * uuid,
                        char              * name,
                        const char        * value);

struct kb_fact *
kb_entity_put_name_fact(struct kb_entity * entity, char * name, const char * value);

struct kb_fact *
kb_entity_find_uuid_fact(struct kb_entity * entity, struct nexus_uuid * uuid);

struct kb_fact *
kb_entity_find_name_fact(struct kb_entity * entity, char * name);

int
kb_entity_del_uuid_fact(struct kb_entity * entity, struct kb_fact * fact);

int
kb_entity_del_name_fact(struct kb_entity * entity, struct kb_fact * fact);


// checks if the entity is out of data or not fully asserted
bool
kb_entity_needs_refresh(struct kb_entity * entity, struct nexus_metadata * metadata);

void
kb_entity_assert_fully(struct kb_entity * entity, struct nexus_metadata * metadata);


struct kb_fact *
__kb_fact_from_db_list(struct list_head * db_list_ptr);

struct kb_fact *
__kb_fact_from_entity_list(struct list_head * entity_list_ptr);

void
kb_fact_update_value(struct kb_fact * fact, const char * value);

void
kb_fact_free(struct kb_fact * cached_fact);

void
kb_fact_warm_up(struct kb_fact * fact);

void
kb_fact_cool_down(struct kb_fact * fact);
