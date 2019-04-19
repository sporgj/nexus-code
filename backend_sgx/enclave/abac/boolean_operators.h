#pragma once

#include <stdbool.h>

int
boolean_operator_execute(char * boolean_str, char * arg1, char * arg2, bool * result);

const char *
boolean_operator_to_datalog_str(char * boolean_str);

bool
boolean_operator_exists(char * boolean_str);
