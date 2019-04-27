#pragma once

#include "abac_types.h"

#include <libnexus_trusted/nexus_uuid.h>
#include <libnexus_trusted/hashmap.h>


// correspond to a particular user_profile, metadata or policy_store
struct __cached_element {
    struct nexus_uuid uuid;
    char *            uuid_str;

    attribute_type_t  attr_type; // denotes whether _isUser/_isObject have been added

    struct hashmap    uuid_facts; // facts indexed by uuid (rules and attributes)
    struct hashmap    name_facts;  // facts indexed by name (sys functions)
};

struct __cached_fact {
    struct hashmap_entry hash_entry;
    struct nexus_uuid    uuid;
    char                 name[ATTRIBUTE_NAME_MAX];

    char               * value;

    bool                 is_inserted;
    bool                 is_rule;

    struct __cached_element * element;
};


struct __cached_element *
cached_element_new(struct nexus_uuid * uuid);

void
cached_element_free(struct __cached_element * cached_element);

struct __cached_fact *
cached_element_put_uuid_fact(struct __cached_element * cached_element,
                             struct nexus_uuid       * uuid,
                             char                    * name,
                             char                    * value);

struct __cached_fact *
cached_element_put_name_fact(struct __cached_element * cached_element,
                             char                    * name,
                             char                    * value);

struct __cached_fact *
cached_element_find_uuid_fact(struct __cached_element * cached_element, struct nexus_uuid * uuid);

struct __cached_fact *
cached_element_find_name_fact(struct __cached_element * cached_element, char * name);

