#pragma once

#include <stdbool.h>

const char *
boolean_operator_to_datalog_str(char * boolean_str);

bool
boolean_operator_exists(char * boolean_str);
