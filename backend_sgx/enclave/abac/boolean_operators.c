#include "abac_internal.h"
#include "boolean_operators.h"
#include "value.h"


struct __bool_op {
    char * name;
    char * datalog_str;
};


static struct __bool_op __boolean_operators[] = {
    { ">",  "_gt" },
    { "<",  "_lt" },
    { ">=", "_ge" },
    { "<=", "_le" },
    { "!=", "_ne" },
    { "==", "=",  },
    { NULL,  NULL },
};

static struct __bool_op *
__find_boolean_operator(char * boolean_str)
{
    struct __bool_op * bool_operator = __boolean_operators;

    while (bool_operator->name != NULL) {
        if (strncmp(boolean_str, bool_operator->name, 5) == 0) {
            return bool_operator;
        }

        bool_operator += 1;
    }

    return NULL;
}

const char *
boolean_operator_to_datalog_str(char * boolean_str)
{
    struct __bool_op * bool_operator = __find_boolean_operator(boolean_str);

    if (bool_operator == NULL) {
        return NULL;
    }

    return bool_operator->datalog_str;
}

bool
boolean_operator_exists(char * boolean_str)
{
    struct __bool_op * bool_operator = __find_boolean_operator(boolean_str);

    if (bool_operator == NULL) {
        return false;
    }

    return true;
}
