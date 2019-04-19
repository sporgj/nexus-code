#pragma once

#include "abac_types.h"

#include <libnexus_trusted/rapidstring.h>

bool
system_function_exists(char * function_name, sys_func_type_t type);

char *
system_function_execute(char * function_name, sys_func_type_t type, void * arg);

int
system_function_export_facts(void * arg, sys_func_type_t type, rapidstring * string_builder);
