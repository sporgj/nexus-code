#include "../enclave_internal.h"

#include "abac_internal.h"
#include "db.h"

#include <libnexus_trusted/rapidstring.h>


static dl_db_t my_database;

static struct list_head cached_facts_list;
static size_t           cached_facts_count;

static size_t           cached_rules_count;

int
db_init()
{
    my_database = datalog_engine_create();

    if (my_database == NULL) {
        log_error("could not create a new datalog engine\n");
        return -1;
    }

    INIT_LIST_HEAD(&cached_facts_list);

    return 0;
}

void
db_exit()
{
    // TODO remove the cached facts
    //

    if (my_database) {
        datalog_engine_destroy(my_database);
    }
}

int
db_ask_permission(perm_type_t        perm_type,
                  struct kb_entity * user_entity,
                  struct kb_entity * object_entity)
{
    char * permission_string = perm_type_to_string(perm_type);

    if (!datalog_engine_is_true(my_database,
                                permission_string,
                                user_entity->uuid_str,
                                object_entity->uuid_str)) {
        nexus_free(permission_string);
        return -1;
    }

    nexus_free(permission_string);

    return 0;
}

int
db_assert_kb_entity_type(struct kb_entity * entity)
{
    char * entity_type_str = NULL;

    if (entity->type_fact && entity->type_fact->is_inserted) {
        return 0;
    }

    if (entity->attr_type == USER_ATTRIBUTE_TYPE) {
        entity_type_str = "_isUser";
    } else if (entity->attr_type == OBJECT_ATTRIBUTE_TYPE) {
        entity_type_str = "_isObject";
    } else {
        log_error("unsupported attribute type\n");
        return -1;
    }

    if (entity->type_fact == NULL) {
        entity->type_fact = kb_entity_put_name_fact(entity, entity_type_str, NULL);
    }

    if (db_assert_fact(entity->type_fact)) {
        log_error("could not assert `%s` entity type\n", entity->uuid_str);
        return -1;
    }

    return 0;
}

int
db_retract_kb_entity_type(struct kb_entity * entity)
{
    if (entity->type_fact == NULL) {
        return 0;
    }

    // we just retract it later
    if (db_retract_fact(entity->type_fact)) {
        log_error("could not retract `%s` entity type\n", entity->uuid_str);
        return -1;
    }

    return 0;
}


static int
__insert_db_fact(dl_db_t      db,
                 const char * predicate,
                 const char * object_name,
                 const char * value)
{
    if (__db_make_literal(predicate,
                          object_name,
                          DATALOG_CONST_TERM,
                          value,
                          DATALOG_CONST_TERM,
                          db)) {
        log_error("__db_make_literal() FAILED\n");
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
db_retract_fact(struct kb_fact * cached_fact)
{
    int mark = dl_mark(my_database);

    if (__insert_db_fact(my_database,
                         cached_fact->name,
                         cached_fact->entity->uuid_str,
                         cached_fact->value)) {
        log_error("__insert_db_fact() FAILED\n");
        goto out_err;
    }

    if (dl_retract(my_database)) {
        log_error("dl_retract() FAILED\n");
        goto out_err;
    }

    cached_fact->is_inserted = true;

    kb_fact_cool_down(cached_fact);

    list_del_init(&cached_fact->db_list);
    cached_facts_count -= 1;

    return 0;

out_err:
    dl_reset(my_database, mark);
    return -1;
}

int
db_assert_fact(struct kb_fact * cached_fact)
{
    int mark = dl_mark(my_database);

    if (__insert_db_fact(my_database,
                         cached_fact->name,
                         cached_fact->entity->uuid_str,
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

    cached_fact->is_inserted = true;

    kb_fact_warm_up(cached_fact);

    list_add(&cached_fact->db_list, &cached_facts_list);

    cached_facts_count += 1;

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

    cached_rules_count += 1;

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

    cached_rules_count -= 1;

    return 0;
out_err:
    dl_reset(my_database, mark);
    return -1;
}

int
__db_push_term(char * term, datalog_term_type_t term_type, dl_db_t db)
{
    if (dl_pushstring(db, term)) {
        log_error("dl_pushstring(`%s`) FAILED\n", term);
        return -1;
    }

    if (term_type == DATALOG_VAR_TERM) {
        if (dl_addvar(db)) {
            log_error("dl_addvar() failed\n");
            return -1;
        }
    } else {
        if (dl_addconst(db)) {
            log_error("dl_addconst() failed\n");
            return -1;
        }
    }

    return 0;
}

int
__db_make_literal(char              * predicate,
                  char              * first_term_str,
                  datalog_term_type_t first_term_type,
                  char              * second_term_str,
                  datalog_term_type_t second_term_type,
                  dl_db_t             db)
{
    if (dl_pushliteral(db)) {
        log_error("dl_pushliteral() for atom FAILED\n");
        return -1;
    }

    {
        if (dl_pushstring(db, predicate)) {
            log_error("dl_pushstring('%s')\n", predicate);
            return -1;
        }

        if (dl_addpred(db)) {
            log_error("dl_addpred() of atom's predicate FAILED\n");
            return -1;
        }
    }

    if (__db_push_term(first_term_str, first_term_type, db)) {
        log_error("db_push_term(`%s`) FAILED\n", first_term_str);
        return -1;
    }

    if (second_term_str && __db_push_term(second_term_str, second_term_type, db)) {
        log_error("db_push_term(`%s`) FAILED\n", second_term_str);
        return -1;
    }

    if (dl_makeliteral(db)) {
        log_error("dl_makeliteral() FAILED\n");
        return -1;
    }

    return 0;
}

int
__db_push_literal(char              * predicate,
                  char              * first_str,
                  datalog_term_type_t first_type,
                  char              * second_str,
                  datalog_term_type_t second_type,
                  dl_db_t             db)
{
    if (__db_make_literal(predicate, first_str, first_type, second_str, second_type, db)) {
        log_error("db_make_literal() FAILED\n");
        return -1;
    }

    if (dl_addliteral(db)) {
        log_error("dl_addliteral() FAILED\n");
        return -1;
    }

    return 0;
}

void
db_export_telemetry(struct nxs_telemetry * telemetry)
{
    if (nexus_enclave_is_current_user_owner()) {
        return;
    }

    telemetry->lua_memory_kilobytes = datalog_engine_lua_kilobytes(my_database);

    telemetry->asserted_facts_count = cached_facts_count;
    telemetry->asserted_rules_count = cached_rules_count;
}

int
UNSAFE_db_print_facts()
{
    struct list_head * curr = NULL;
    rapidstring string_builder;

    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    rs_init(&string_builder);

    {
        char tmp_buffer[32] = { 0 };

        snprintf(tmp_buffer, sizeof(tmp_buffer), "%zu Facts", cached_facts_count);
        rs_cat(&string_builder, tmp_buffer);

        rs_cat(&string_builder, "\n-----------\n");
    }

    list_for_each(curr, &cached_facts_list) {
        struct kb_fact * cached_fact = __kb_fact_from_db_list(curr);

        rs_cat(&string_builder, cached_fact->name);
        rs_cat_n(&string_builder, "(", 1);
        rs_cat(&string_builder, cached_fact->entity->uuid_str);

        if (cached_fact->value) {
            rs_cat_n(&string_builder, ", \"", 3);
            rs_cat(&string_builder, cached_fact->value);
        }

        rs_cat_n(&string_builder, "\")\n", 3);
    }

    ocall_print(rs_data_c(&string_builder));

    rs_free(&string_builder);

    return 0;
}
