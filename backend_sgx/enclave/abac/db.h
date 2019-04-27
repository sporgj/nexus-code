#pragma once

#include <stdbool.h>

#include "abac_types.h"
#include "fact.h"


#include "./datalog-engine/engine.h"


extern dl_db_t my_database;


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
