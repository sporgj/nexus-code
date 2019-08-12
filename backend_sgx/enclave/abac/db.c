#include "../enclave_internal.h"

#include "abac_internal.h"
#include "db.h"

#include "./datalog-engine/engine.h"

#include <libnexus_trusted/rapidstring.h>


#define MAX_CACHED_FACTS     (50)


static dl_db_t my_database;

static size_t           cached_facts_count;
static size_t           cached_rules_count;

struct kb_entity *
kb_entity_new(struct nexus_uuid * uuid, attribute_type_t attribute_type)
{
    struct kb_entity * entity = nexus_malloc(sizeof(struct kb_entity));

    nexus_uuid_copy(uuid, &entity->uuid);
    entity->uuid_str = nexus_uuid_to_hex(uuid);

    entity->attr_type = attribute_type;

    return entity;
}

void
kb_entity_free(struct kb_entity * entity)
{
    nexus_free(entity->uuid_str);
    nexus_free(entity);
}

int
db_init()
{
    my_database = datalog_engine_create();

    if (my_database == NULL) {
        log_error("could not create a new datalog engine\n");
        return -1;
    }

    return 0;
}

void
db_exit()
{
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

    if (entity->attr_type == USER_ATTRIBUTE_TYPE) {
        entity_type_str = "_isUser";
    } else if (entity->attr_type == OBJECT_ATTRIBUTE_TYPE) {
        entity_type_str = "_isObject";
    } else {
        log_error("unsupported attribute type\n");
        return -1;
    }

    if (db_assert_fact(entity, entity_type_str, NULL)) {
        log_error("could not assert `%s` entity type\n", entity->uuid_str);
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
db_retract_fact(struct kb_entity * entity, const char * predicate, const char * value)
{
    int mark = dl_mark(my_database);

    if (__insert_db_fact(my_database, predicate, entity->uuid_str, value)) {
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
db_assert_fact(struct kb_entity * entity, const char * predicate, const char * value)
{
    int mark = -1;
    int ret  = -1;

    mark = dl_mark(my_database);

    if (__insert_db_fact(my_database, predicate, entity->uuid_str, value)) {
        log_error("__insert_db_fact() FAILED\n");
        goto out_err;
    }

    ret = dl_assert(my_database);

    if (ret) {
        if (ret == -1) {
            log_error("unsafe fact asserted\n");
        } else {
            log_error("dl_assert() reported an error\n");
        }

        goto out_err;
    }

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
    if (strnlen(term, ATTRIBUTE_VALUE_SIZE) == 0) {
        return 0;
    }

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

    telemetry->asserted_facts_count = dl_count_facts(my_database);
    telemetry->asserted_rules_count = dl_count_rules(my_database);
}

// TODO
int
UNSAFE_db_print_facts()
{
    struct list_head * curr = NULL;
    rapidstring string_builder;

    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    return -1;
}

void
db_clear_facts()
{
    if (nexus_enclave_is_current_user_owner()) {
        return;
    }

    dl_clear_facts(my_database);

    lua_gc(my_database, LUA_GCCOLLECT, 0);

    cached_facts_count = 0;
}

void
db_clear_rules()
{
    if (nexus_enclave_is_current_user_owner()) {
        return;
    }

    dl_clear_rules(my_database);

    lua_gc(my_database, LUA_GCCOLLECT, 0);

    cached_rules_count = 0;
}

int
db_evict_entity(struct kb_entity * entity)
{
    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    int evict_count = dl_evict_entity(my_database, entity->uuid_str);

    if (evict_count == -1) {
        log_error("could not evict '%s' from knowledgebase\n", entity->uuid_str);
        return -1;
    }

#if 0
    if (evict_count > 0) {
        nexus_printf("evicted %d facts for `%s`\n", evict_count, entity->uuid_str);
    }
#endif

    cached_facts_count -= evict_count;

    return 0;
}
