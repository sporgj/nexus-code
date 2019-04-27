#include "abac_internal.h"
#include "db.h"


dl_db_t my_database;


int
__get_cached_element_type(char * dest_buffer, attribute_type_t attr_type)
{
    if (attr_type == USER_ATTRIBUTE_TYPE) {
        strncpy(dest_buffer, "_isUser", ATTRIBUTE_NAME_MAX);
    } else if (attr_type == OBJECT_ATTRIBUTE_TYPE) {
        strncpy(dest_buffer, "_isObject", ATTRIBUTE_NAME_MAX);
    } else {
        return -1;
    }

    return 0;
}

int
db_assert_cached_element_type(struct __cached_element * cached_element, attribute_type_t attr_type)
{
    struct __cached_fact tmp_fact = { 0 };

    if (__get_cached_element_type(&tmp_fact.name, attr_type)) {
        log_error("could not get cached_element type\n");
        return -1;
    }

    tmp_fact.element = cached_element;

    if (db_assert_fact(&tmp_fact)) {
        log_error("could not assert `%s` cached_element type\n", tmp_fact.name);
        return -1;
    }

    cached_element->attr_type = attr_type;

    return 0;
}

int
db_retract_cached_element_type(struct __cached_element * cached_element)
{
    struct __cached_fact tmp_fact = { 0 };

    if (__get_cached_element_type(&tmp_fact.name, cached_element->attr_type)) {
        log_error("could not get cached_element type\n");
        return -1;
    }

    tmp_fact.element = cached_element;

    if (db_retract_fact(&tmp_fact)) {
        log_error("could not retract `%s` cached_element type\n", tmp_fact.name);
        return -1;
    }

    cached_element->attr_type = 0;

    return 0;
}


static int
__insert_db_fact(dl_db_t      db,
                 const char * attribute_name,
                 const char * object_name,
                 const char * value)
{
    // goal: name(object_name, value)
    if (dl_pushliteral(db)) {
        log_error("dl_pushliteral() for fact FAILED\n");
        goto out_err;
    }

    // the name is the predicate
    {
        if (dl_pushstring(db, attribute_name)) {
            log_error("pushing rule predicate(`%s`) failed\n", attribute_name);
            goto out_err;
        }

        if (dl_addpred(db)) {
            log_error("dl_addpred() of atom's predicate FAILED\n");
            goto out_err;
        }
    }

    // add the object name
    {
        if (dl_pushstring(db, object_name)) {
            log_error("could not push string `%s`\n", object_name);
            goto out_err;
        }

        if (dl_addconst(db)) {
            log_error("could not add constant\n");
            goto out_err;
        }
    }

    if (value) {
        if (dl_pushstring(db, value)) {
            log_error("could not push string `%s`\n", value);
            goto out_err;
        }

        if (dl_addconst(db)) {
            log_error("could not add constant\n");
            goto out_err;
        }
    }

    if (dl_makeliteral(db)) {
        log_error("dl_makeliteral() FAILED\n");
        goto out_err;
    }

    // push the head and make a clause
    {
        if (dl_pushhead(db)) {
            log_error("dl_pushhead() FAILED\n");
            goto out_err;
        }

        if (dl_makeclause(db)) {
            log_error("dl_makeclause() FAILED on __assert_fact()\n");
            goto out_err;
        }
    }

    return 0;
out_err:
    return -1;
}

int
db_retract_fact(struct __cached_fact * cached_fact)
{
    int mark = dl_mark(my_database);

    if (__insert_db_fact(my_database,
                         cached_fact->name,
                         cached_fact->element->uuid_str,
                         cached_fact->value)) {
        log_error("__insert_db_fact() FAILED\n");
        goto out_err;
    }

    if (dl_retract(my_database)) {
        log_error("dl_retract() FAILED\n");
        goto out_err;
    }

    return 0;

out_err:
    dl_reset(my_database, mark);
    return -1;
}

int
db_assert_fact(struct __cached_fact * cached_fact)
{
    int mark = dl_mark(my_database);

    if (__insert_db_fact(my_database,
                         cached_fact->name,
                         cached_fact->element->uuid_str,
                         cached_fact->value)) {
        log_error("__insert_db_fact() FAILED\n");
        goto out_err;
    }

    int ret = dl_assert(my_database);

    if (ret) {
        if (ret == -1) {
            log_error("unsafe fact asserted\n");
        } else {
            log_error("dl_assert() reported an error\n");
        }

        goto out_err;
    }

    return 0;
out_err:
    dl_reset(my_database, mark);
    return -1;
}

int
db_assert_policy_rule(struct policy_rule * rule)
{
    int mark = dl_mark(my_database);

    if (policy_rule_to_db(rule, my_database)) {
        log_error("policy_rule_to_db() FAILED\n");
        goto out_err;
    }

    int ret = dl_assert(my_database);

    if (ret) {
        if (ret == -1) {
            log_error("unsafe rule asserted\n");
        } else {
            log_error("could not assert rule\n");
        }

        goto out_err;
    }

    return 0;
out_err:
    dl_reset(my_database, mark);
    return -1;
}

int
db_retract_policy_rule(struct policy_rule * rule)
{
    int mark = dl_mark(my_database);

    if (policy_rule_to_db(rule, my_database)) {
        log_error("policy_rule_to_db() FAILED\n");
        goto out_err;
    }

    if (dl_retract(my_database)) {
        log_error("dl_retract() FAILED\n");
        goto out_err;
    }

    return 0;
out_err:
    dl_reset(my_database, mark);
    return -1;
}

