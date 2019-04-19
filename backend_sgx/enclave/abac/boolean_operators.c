#include "abac_internal.h"
#include "boolean_operators.h"


struct __bool_op {
    char * name;
    char * datalog_str;
    char * (*handler)(char * arg1, char * arg2);
};



static int
__handle_greater_than(char * arg1, char * arg2)
{
    // TODO
    return -1;
}

static int
__handle_lesser_than(char * arg1, char * arg2)
{
    // TODO
    return -1;
}

static int
__handle_greater_or_equals(char * arg1, char * arg2)
{
    // TODO
    return -1;
}

static int
__handle_lesser_or_equals(char * arg1, char * arg2)
{
    // TODO
    return -1;
}

static int
__handle_double_equals(char * arg1, char * arg2)
{
    // TODO
    return -1;
}

static struct __bool_op __boolean_operators[] = {
    { ">",  "_gt", __handle_greater_than },
    { "<",  "_lt", __handle_lesser_than },
    { ">=", "_ge", __handle_greater_or_equals },
    { "<=", "_le", __handle_lesser_or_equals },
    { "==", "_le", __handle_double_equals },
    { NULL,  NULL, NULL },
};

static struct __bool_op *
__find_boolean_operator(char * boolean_str)
{
    struct __bool_op * bool_operator = __boolean_operators;

    while (bool_operator->name != NULL) {
        size_t len = strnlen(bool_operator->name, 5);

        if (strncmp(bool_operator->name, boolean_str, len) == 0) {
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

int
boolean_operator_execute(char * boolean_str, char * arg1, char * arg2, bool * result)
{
    struct __bool_op * bool_operator = __find_boolean_operator(boolean_str);

    if (bool_operator == NULL) {
        log_error("could not find `%s` boolean operator\n", boolean_str);
        return NULL;
    }

    return bool_operator->handler(arg1, arg2);
}
