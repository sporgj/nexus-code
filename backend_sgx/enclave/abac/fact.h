#pragma once

#include "abac_types.h"

#include <libnexus_trusted/nexus_uuid.h>
#include <libnexus_trusted/hashmap.h>
#include <libnexus_trusted/list.h>

struct kb_fact;


// correspond to a particular user_profile, metadata or policy_store
struct kb_entity {
    struct nexus_uuid uuid;
    char *            uuid_str;

    attribute_type_t  attr_type; // denotes whether _isUser/_isObject have been added
    const struct kb_fact * type_fact; // will be stored in the db

    struct hashmap    uuid_facts; // facts indexed by uuid (rules and attributes)
    struct hashmap    name_facts;  // facts indexed by name (sys functions)
};

struct kb_fact {
    struct hashmap_entry hash_entry;
    struct nexus_uuid    uuid;
    char                 name[ATTRIBUTE_NAME_MAX];

    char               * value;

    bool                 is_inserted;
    bool                 is_rule;

    struct kb_entity   * entity;

    struct list_head     fact_list;
};


struct kb_entity *
kb_entity_new(struct nexus_uuid * uuid);

void
kb_entity_free(struct kb_entity * entity);

struct kb_fact *
kb_entity_put_uuid_fact(struct kb_entity  * entity,
                        struct nexus_uuid * uuid,
                        char              * name,
                        char              * value);

struct kb_fact *
kb_entity_put_name_fact(struct kb_entity * entity, char * name, char * value);

struct kb_fact *
kb_entity_find_uuid_fact(struct kb_entity * entity, struct nexus_uuid * uuid);

struct kb_fact *
kb_entity_find_name_fact(struct kb_entity * entity, char * name);



void
kb_fact_free(struct kb_fact * cached_fact);
