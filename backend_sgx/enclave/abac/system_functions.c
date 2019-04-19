#include "system_functions.h"
#include "abac_internal.h"

#include "../metadata.h"
#include "../dentry.h"

#include <libnexus_trusted/rapidstring.h>


struct __sys_func {
    char * name;
    char * (*handler)(void * arg);

    sys_func_type_t type;
};


char *
__handle_uname(void * arg)
{
    // TODO
    return NULL;
}

char *
__handle_upkey(void * arg)
{
    // TODO
    return NULL;
}

char *
__handle_opath(void * arg)
{
    struct nexus_metadata * metadata = arg;

    struct nexus_dentry * dentry = metadata_get_dentry(metadata);

    if (dentry) {
        return dentry_get_fullpath(dentry);
    }

    return NULL;
}

char *
__handle_oname(void * arg)
{
    struct nexus_metadata * metadata = arg;

    struct nexus_dentry * dentry = metadata_get_dentry(metadata);

    if (dentry) {
        return strndup(dentry->name, NEXUS_NAME_MAX);
    }

    return NULL;
}

char *
__handle_osize(void * arg)
{
    struct nexus_metadata * metadata = arg;

    if (metadata->type == NEXUS_DIRNODE) {
        return metadata->dirnode->dir_entry_count;
    } else if (metadata->type == NEXUS_FILENODE) {
        return metadata->filenode->filesize;
    }

    return NULL;
}

char *
__handle_otype(void * arg)
{
    struct nexus_metadata * metadata = arg;

    if (metadata->type == NEXUS_DIRNODE) {
        return strndup("dir", 4);
    } else if (metadata->type == NEXUS_FILENODE) {
        return strndup("file", 5);
    }

    return NULL;
}


static struct __sys_func system_functions[] = {
    { "@uname", __handle_uname, USER_FUNCTION },
    { "@upkey", __handle_upkey, USER_FUNCTION },

    { "@opath", __handle_opath, OBJECT_FUNCTION },
    { "@oname", __handle_oname, OBJECT_FUNCTION },
    { "@osize", __handle_osize, OBJECT_FUNCTION },
    { "@otype", __handle_otype, OBJECT_FUNCTION },
    { NULL, NULL, 0 }
};


static struct __sys_func *
__find_system_function(char * function_name)
{
    struct __sys_func * sys_function = system_functions;

    while (sys_function->name != NULL) {
        size_t len = strnlen(sys_function->name, SYSTEM_FUNC_MAX_LENGTH);

        if (strncmp(sys_function->name, function_name, len) == 0) {
            return sys_function;
        }

        sys_function += 1;
    }

    return NULL;
}

bool
system_function_exists(char * function_name, sys_func_type_t type)
{
    struct __sys_func * sys_function = __find_system_function(function_name);

    if (sys_function == NULL || sys_function->type != type) {
        return false;
    }

    return true;
}

char *
system_function_execute(char * function_name, sys_func_type_t type, void * arg)
{
    struct __sys_func * sys_function = __find_system_function(function_name);

    if (sys_function == NULL) {
        log_error("could not find `%s` system function\n", function_name);
        return NULL;
    }

    if (sys_function->type != type) {
        if (sys_function->type == USER_FUNCTION) {
            log_error("`%s` is a user function, but argument is an object function\n");
        } else {
            log_error("`%s` is an object function, but argument is a user function\n");
        }

        return NULL;
    }

    return sys_function->handler(arg);
}

int
system_function_export_facts(void * arg, sys_func_type_t type, rapidstring * string_builder)
{
    struct __sys_func * sys_function = system_functions;
    char * term = NULL;
    size_t skipped = 0;

    if (type == USER_FUNCTION) {
        term = "(u, \"";
    } else if (type == OBJECT_FUNCTION) {
        term = "(o, \"";
    } else {
        log_error("unknown sys_function type\n");
        return -1;
    }

    // XXX: optimize
    for (; sys_function->name != NULL; sys_function++) {
        if (sys_function->type != type) {
            continue;
        }

        char * result = sys_function->handler(arg);
        if (result == NULL) {
            skipped += 1;
            continue;
        }

        rs_cat(string_builder, sys_function->name);
        rs_cat_n(string_builder, term, 5);
        rs_cat(string_builder, result);
        rs_cat_n(string_builder, "\").\n", 4);

        nexus_free(result);
    }

    return 0;
}
