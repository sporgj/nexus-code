#pragma once

#include <stdbool.h>

#include "abac_types.h"



struct nxs_telemetry;

typedef enum {
    DATALOG_VAR_TERM = 1,
    DATALOG_CONST_TERM
} datalog_term_type_t;


struct kb_entity {
    struct nexus_uuid       uuid;
    char                  * uuid_str;
    size_t                  metadata_version;
    attribute_type_t        attr_type; // denotes whether _isUser/_isObject
};


struct kb_entity *
kb_entity_new(struct nexus_uuid * uuid, attribute_type_t attribute_type);

void
kb_entity_free(struct kb_entity * entity);


int
db_init();

void
db_exit();

int
db_ask_permission(perm_type_t        perm_type,
                  struct kb_entity * user_entity,
                  struct kb_entity * obj_entity);

int
db_retract_fact(struct kb_entity * entity, const char * predicate, const char * value);

int
db_assert_fact(struct kb_entity * entity, const char * predicate, const char * value);

int
db_assert_policy_rule(struct policy_rule * rule);

int
db_retract_policy_rule(struct policy_rule * rule);


// these are to be used with care

int
__db_make_literal(char              * predicate,
                  char              * first_term_str,
                  datalog_term_type_t first_term_type,
                  char              * second_term_str,
                  datalog_term_type_t second_term_type,
                  dl_db_t             db);


int
__db_push_literal(char              * predicate,
                  char              * first_term_str,
                  datalog_term_type_t first_term_type,
                  char              * second_term_str,
                  datalog_term_type_t second_term_type,
                  dl_db_t             db);

int
__db_push_term(char * term, datalog_term_type_t term_type, dl_db_t db);


int
UNSAFE_db_print_facts();

void
db_export_telemetry(struct nxs_telemetry * telemetry);

void
db_clear_facts();

void
db_clear_rules();

int
db_evict_entity(struct kb_entity * entity);
