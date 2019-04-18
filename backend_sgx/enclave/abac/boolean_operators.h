#pragma once

#include <stdbool.h>

int
boolean_operator_execute(char * boolean_str, char * arg1, char * arg2, bool * result);

bool
boolean_operator_exists(char * boolean_str);
