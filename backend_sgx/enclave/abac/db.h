#pragma once

#include <stdbool.h>

#include "abac_types.h"
#include "fact.h"


#include "./datalog-engine/engine.h"


extern dl_db_t my_database;


typedef enum {
    DATALOG_VAR_TERM = 1,
    DATALOG_CONST_TERM
} datalog_term_type_t;


int
db_retract_fact(struct __cached_fact * cached_fact);

int
db_assert_fact(struct __cached_fact * cached_fact);

int
db_assert_cached_element_type(struct __cached_element * cached_element, attribute_type_t attr_type);

int
db_retract_cached_element_type(struct __cached_element * cached_element);

int
db_assert_policy_rule(struct policy_rule * rule);

int
db_retract_policy_rule(struct policy_rule * rule);

int
db_make_literal(char              * predicate,
                char              * first_term_str,
                datalog_term_type_t first_term_type,
                char              * second_term_str,
                datalog_term_type_t second_term_type,
                dl_db_t             db);
int
db_push_literal(char              * predicate,
                char              * first_term_str,
                datalog_term_type_t first_term_type,
                char              * second_term_str,
                datalog_term_type_t second_term_type,
                dl_db_t             db);

int
db_push_term(char * term, datalog_term_type_t term_type, dl_db_t db);
