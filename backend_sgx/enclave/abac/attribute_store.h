/**
 * Manages all the user-defined attributes
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */

#pragma once

#include "abac_internal.h"

struct attribute_store {
    struct nexus_uuid        my_uuid;
    struct nexus_uuid        root_uuid;

    size_t                   count;

    struct nexus_mac         mac;

    struct list_head         list_attribute_terms;

    struct nexus_metadata  * metadata;
};


typedef enum {
    USER_ATTRIBUTE_TYPE,
    OBJECT_ATTRIBUTE_TYPE
} attribute_type_t;


struct attribute_term {
    struct list_head         list_entry;
    attribute_type_t         type;
    char                     name[ATTRIBUTE_NAME_MAX];
    struct nexus_uuid        uuid;
};



struct attribute_store *
attribute_store_create(struct nexus_uuid * uuid, struct nexus_uuid * root_uuid);

void
attribute_store_destroy(struct attribute_store * attr_store);


const struct attribute_term *
attribute_store_find_uuid(struct attribute_store * attr_store, struct nexus_uuid * uuid);

const struct attribute_term *
attribute_store_find_name(struct attribute_store * attr_store, char * name);


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

