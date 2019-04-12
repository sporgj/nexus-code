#pragma once

#include "abac_types.h"

bool
system_function_exists(char * function_name, sys_func_type_t type);

char *
system_function_execute(char * function_name, sys_func_type_t type, void * arg);
