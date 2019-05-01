#pragma once

#include "abac_types.h"
#include "value.h"

#include <libnexus_trusted/rapidstring.h>

struct __sys_func;
struct nexus_metadata;

const char *
sys_func_get_name(struct __sys_func * sys_func);

bool
system_function_exists(char * function_name, sys_func_type_t type);

// returns a list of sysstem functions filtered by type
struct nexus_list *
system_function_export_sysfuncs(sys_func_type_t type);

char *
system_function_run(struct __sys_func * sys_func, struct nexus_metadata * metadata);
