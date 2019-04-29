#include "abac_internal.h"
#include "boolean_operators.h"
#include "value.h"


struct __bool_op {
    char * name;
    char * datalog_str;
    int    (*handler)(struct abac_value * arg1, struct abac_value * arg2, bool * result_bool);
};



static int
__handle_greater_than(struct abac_value * arg1, struct abac_value * arg2, bool * result_bool)
{
    if (arg1->type == ABAC_VALUE_NUMBER && arg2->type == ABAC_VALUE_NUMBER) {
        *result_bool = (arg1->int_val > arg2->int_val);
        return 0;
    } else if (arg1->type == ABAC_VALUE_STRING && arg2->type == ABAC_VALUE_STRING) {
        *result_bool = (strncmp(arg1->str_val, arg2->str_val, arg1->data_sz) > 0);
        return 0;
    }

    log_error("mimatched data types\n");

    return -1;
}

static int
__handle_lesser_than(struct abac_value * arg1, struct abac_value * arg2, bool * result_bool)
{
    if (arg1->type == ABAC_VALUE_NUMBER && arg2->type == ABAC_VALUE_NUMBER) {
        *result_bool = (arg1->int_val < arg2->int_val);
        return 0;
    } else if (arg1->type == ABAC_VALUE_STRING && arg2->type == ABAC_VALUE_STRING) {
        *result_bool = (strncmp(arg1->str_val, arg2->str_val, arg1->data_sz) < 0);
        return 0;
    }

    log_error("mimatched data types\n");

    return -1;
}

static int
__handle_greater_or_equals(struct abac_value * arg1, struct abac_value * arg2, bool * result_bool)
{
    if (arg1->type == ABAC_VALUE_NUMBER && arg2->type == ABAC_VALUE_NUMBER) {
        *result_bool = (arg1->int_val >= arg2->int_val);
        return 0;
    } else if (arg1->type == ABAC_VALUE_STRING && arg2->type == ABAC_VALUE_STRING) {
        *result_bool = (strncmp(arg1->str_val, arg2->str_val, arg1->data_sz) >= 0);
        return 0;
    }

    log_error("mimatched data types\n");

    return -1;
}

static int
__handle_lesser_or_equals(struct abac_value * arg1, struct abac_value * arg2, bool * result_bool)
{
    if (arg1->type == ABAC_VALUE_NUMBER && arg2->type == ABAC_VALUE_NUMBER) {
        *result_bool = (arg1->int_val <= arg2->int_val);
        return 0;
    } else if (arg1->type == ABAC_VALUE_STRING && arg2->type == ABAC_VALUE_STRING) {
        *result_bool = (strncmp(arg1->str_val, arg2->str_val, arg1->data_sz) <= 0);
        return 0;
    }

    log_error("mimatched data types\n");

    return -1;
}

static int
__handle_double_equals(struct abac_value * arg1, struct abac_value * arg2, bool * result_bool)
{
    if (arg1->type == ABAC_VALUE_NUMBER && arg2->type == ABAC_VALUE_NUMBER) {
        *result_bool = (arg1->int_val == arg2->int_val);
        return 0;
    } else if (arg1->type == ABAC_VALUE_STRING && arg2->type == ABAC_VALUE_STRING) {
        *result_bool = (strncmp(arg1->str_val, arg2->str_val, arg1->data_sz) == 0);
        return 0;
    }

    log_error("mismatched data types\n");

    return -1;
}

static struct __bool_op __boolean_operators[] = {
    { ">",  "_gt", __handle_greater_than },
    { "<",  "_lt", __handle_lesser_than },
    { ">=", "_ge", __handle_greater_or_equals },
    { "<=", "_le", __handle_lesser_or_equals },
    { "==", "=", __handle_double_equals },
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
boolean_operator_execute(char              * boolean_str,
                         struct abac_value * arg1,
                         struct abac_value * arg2,
                         bool              * result)
{
    struct __bool_op * bool_operator = __find_boolean_operator(boolean_str);

    if (bool_operator == NULL) {
        log_error("could not find `%s` boolean operator\n", boolean_str);
        return NULL;
    }

    return bool_operator->handler(arg1, arg2, result);
}
