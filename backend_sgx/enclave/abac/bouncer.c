#include "abac_internal.h"

#include "./datalog-engine/engine.h"

#include "../enclave_internal.h"

#include <libnexus_trusted/nexus_lru.h>
#include <libnexus_trusted/nexus_uuid.h>
#include <libnexus_trusted/hashmap.h>

#include "system_functions.h"

#include "value.h"
#include "fact.h"
#include "db.h"


struct abac_request {
    struct policy_store     * policy_store;
    struct attribute_store  * attribute_store;

    struct nexus_metadata   * obj_metadata;
    struct kb_entity        * obj_entity;

    struct nexus_metadata   * usr_metadata;

    perm_type_t               perm_type;
};


static struct nexus_lru * cached_obj_entities = NULL;

static struct kb_entity * user_profile_entity = NULL;
static struct kb_entity * policy_store_entity = NULL;

static void
__destroy_abac_request(struct abac_request * abac_req);

static struct kb_entity *
__cache_obj_entity(struct nexus_metadata * metadata);



static int
__register_fact_with_db(struct kb_entity * entity, struct kb_fact * cached_fact, char * value)
{
    if (cached_fact->is_inserted) {
        if (strncmp(cached_fact->value, value, ATTRIBUTE_VALUE_SIZE) == 0) {
            return 0;
        }

        // retract from datalog engine and update the value
        if (db_retract_fact(cached_fact)) {
            log_error("db_retract_fact() FAILED\n");
            return -1;
        }

        nexus_free(cached_fact->value);
        cached_fact->is_inserted = false;
    }

    cached_fact->value = value;

    if (db_assert_fact(cached_fact)) {
        log_error("db_retract_fact() FAILED\n");
        return -1;
    }

    cached_fact->is_inserted = true;

    return 0;
}


// --[[ system facts

static int
__insert_system_functions(void              * user_or_object,
                          struct kb_entity  * entity,
                          struct nexus_list * sysfacts_list)
{
    struct nexus_list_iterator * iter = list_iterator_new(sysfacts_list);

    struct kb_fact * cached_fact = NULL;

    while (list_iterator_is_valid(iter)) {
        struct __sys_func * sys_func = list_iterator_get(iter);

        const char * name      = sys_func_get_name(sys_func);
        char *       new_value = system_function_run(sys_func, user_or_object);

        if (new_value == NULL) {
            // TODO report here
            goto next;
        }

        // get the cached fact and compare its value
        cached_fact = kb_entity_find_name_fact(entity, (char *)name);

        if (cached_fact) {
            // if the value is unchanged, let's skip
            if ((strncmp(new_value, cached_fact->value, ATTRIBUTE_VALUE_SIZE) == 0)) {
                nexus_free(new_value);
                goto next;
            }
        } else {
            cached_fact = kb_entity_put_name_fact(entity, name, new_value);
        }

        if (__register_fact_with_db(entity, cached_fact, new_value)) {
            list_iterator_free(iter);
            log_error("__register_fact_with_db() FAILED\n");
            return -1;
        }

next:
        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return 0;
}

static int
__abac_request_insert_sysfuncs(struct abac_request * abac_req)
{
    struct nexus_list * usr_sysfacts = NULL;
    struct nexus_list * obj_sysfacts = NULL;

    int ret = -1;


    if (kb_entity_needs_refresh(user_profile_entity, abac_req->usr_metadata)) {
        usr_sysfacts = system_function_export_sysfuncs(USER_FUNCTION);

        if (__insert_system_functions(abac_req->usr_metadata, user_profile_entity, usr_sysfacts)) {
            log_error("could not insert user system functions\n");
            goto out_err;
        }

        return 0;
    }

    if (abac_req->obj_metadata
        && kb_entity_needs_refresh(abac_req->obj_entity, abac_req->obj_metadata)) {
        obj_sysfacts = system_function_export_sysfuncs(OBJECT_FUNCTION);

        if (__insert_system_functions(abac_req->obj_metadata, abac_req->obj_entity, obj_sysfacts)) {
            log_error("could not insert user system functions\n");
            goto out_err;
        }
    }


    ret = 0;
out_err:
    if (usr_sysfacts) {
        nexus_list_destroy(usr_sysfacts);
        nexus_free(usr_sysfacts);
    }

    if (obj_sysfacts) {
        nexus_list_destroy(obj_sysfacts);
        nexus_free(obj_sysfacts);
    }

    return ret;
}

// --]] system facts


// --[[ attributes

static int
__register_attribute_fact(struct kb_entity  * entity,
                          struct nexus_uuid * attr_uuid,
                          char              * name,
                          char              * value)
{
    struct kb_fact * cached_fact = NULL;

    cached_fact = kb_entity_find_uuid_fact(entity, attr_uuid);

    if (cached_fact == NULL) {
        cached_fact = kb_entity_put_uuid_fact(entity, attr_uuid, name, value);
    }

    return __register_fact_with_db(entity, cached_fact, value);
}

static int
__insert_attribute_table(struct abac_request   * abac_req,
                         struct kb_entity      * entity,
                         struct nexus_metadata * metadata)
{
    struct hashmap_iter iter;

    struct attribute_table * attribute_table = metadata_get_attribute_table(metadata);

    if (!kb_entity_needs_refresh(entity, metadata)) {
        return 0;
    }

    if (attribute_table->generation == entity->attribute_table_generation) {
        return 0;
    }

    hashmap_iter_init(&attribute_table->attribute_map, &iter);

    // start iterating the attribute table
    do {
        const struct attribute_term * attr_term;

        struct attribute_entry      * attr_entry = hashmap_iter_next(&iter);

        if (attr_entry == NULL) {
            break;
        }

        attr_term = attribute_store_find_uuid(abac_req->attribute_store, &attr_entry->attr_uuid);

        if (attr_term == NULL) {
            // TODO maybe report here?
            continue;
        }

        if (__register_attribute_fact(entity,
                                      &attr_entry->attr_uuid,
                                      attr_term->name,
                                      attr_entry->attr_val)) {
            log_error("could not push attribute pair (%s)\n", attr_term->name);
            return -1;
        }
    } while (1);

    entity->attribute_table_generation = attribute_table->generation;

    return 0;
}

static int
__abac_request_insert_attributes(struct abac_request * abac_req)
{
    // insert the user_profile attribute table
    if (__insert_attribute_table(abac_req, user_profile_entity, abac_req->usr_metadata)) {
        log_error("could not insert user_profile attribute table into database\n");
        goto out_err;
    }

    // insert the metadata attribute table
    if (abac_req->obj_metadata
        && (__insert_attribute_table(abac_req, abac_req->obj_entity, abac_req->obj_metadata))) {
        log_error("could not insert object attribute table into database\n");
        goto out_err;
    }

    return 0;
out_err:
    return -1;
}

// --]] attributes


// --[[ rules

static int
__insert_policy_rule(struct abac_request * abac_req, struct policy_rule * rule)
{
    struct kb_fact * cached_fact = NULL;

    cached_fact = kb_entity_find_uuid_fact(policy_store_entity, &rule->rule_uuid);

    if (cached_fact == NULL) {
        cached_fact
            = kb_entity_put_uuid_fact(policy_store_entity, &rule->rule_uuid, "", NULL);
        if (cached_fact == NULL) {
            log_error("could not cache policy rule\n");
            goto out_err;
        }

        cached_fact->is_rule = true;
    }

    if (cached_fact->is_inserted == false) {
        if (db_assert_policy_rule(rule)) {
            log_error("db_assert_policy_rule() FAILED\n");
            goto out_err;
        }

        cached_fact->is_inserted = true;
    }

    return 0;
out_err:
    return -1;
}

    static int
__abac_request_insert_rules(struct abac_request * abac_req)
{
    struct nexus_list_iterator * iter = NULL;

    if ((abac_req->policy_store->rules_count == 0)
        || !kb_entity_needs_refresh(policy_store_entity, abac_req->policy_store->metadata)) {
        return 0;
    }

    iter = list_iterator_new(&abac_req->policy_store->rules_list);

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        if (__insert_policy_rule(abac_req, rule)) {
            list_iterator_free(iter);
            log_error("__insert_policy_rule() FAILED\n");
            return -1;
        }

        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));

    list_iterator_free(iter);

    kb_entity_assert_fully(policy_store_entity, abac_req->policy_store->metadata);

    return 0;
}

// --]] rules


static struct abac_request *
__create_abac_request(struct nexus_metadata * metadata, perm_type_t perm_type)
{
    struct abac_request * abac_req = nexus_malloc(sizeof(struct abac_request));

    abac_req->obj_metadata = metadata;
    abac_req->perm_type    = perm_type;

    abac_req->policy_store = abac_acquire_policy_store(NEXUS_FREAD);
    if (abac_req->policy_store == NULL) {
        log_error("could not acquire policy_store\n");
        return NULL;
    }

    abac_req->attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);
    if (abac_req->attribute_store == NULL) {
        abac_release_policy_store();
        log_error("could not acquire attribute_store\n");
        return NULL;
    }

    struct user_profile * user_profile = abac_acquire_current_user_profile(NEXUS_FREAD);
    if (user_profile == NULL) {
        abac_release_policy_store();
        abac_release_attribute_store();
        return NULL;
    }

    abac_req->usr_metadata = user_profile->metadata;

    if (abac_req->obj_metadata) {
        abac_req->obj_entity = __cache_obj_entity(abac_req->obj_metadata);
        if (abac_req->obj_entity == NULL) {
            log_error("__upsert_entity() for metadata failed FAILED\n");
            goto out_err;
        }
    }

    return abac_req;
out_err:
    __destroy_abac_request(abac_req);

    return NULL;
}

static void
__destroy_abac_request(struct abac_request * abac_req)
{
    abac_release_policy_store();
    abac_release_attribute_store();
    abac_release_current_user_profile();

    nexus_free(abac_req);
}

static int
__init_user_attributes()
{
    struct abac_request * abac_req = NULL;

    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    abac_req = __create_abac_request(NULL, PERM_READ);
    if (abac_req == NULL) {
        log_error("__create_abac_request() FAILED\n");
        return -1;
    }

    if (db_assert_kb_entity_type(user_profile_entity, USER_ATTRIBUTE_TYPE)) {
        log_error("db_assert_kb_entity_type() FAILED\n");
        return -1;
    }

    if (__abac_request_insert_attributes(abac_req)) {
        log_error("__abac_request_insert_attributes() FAILED\n");
        __destroy_abac_request(abac_req);
        return -1;
    }

    if (__abac_request_insert_sysfuncs(abac_req)) {
        log_error("__abac_request_insert_sysfuncs() FAILED\n");
        __destroy_abac_request(abac_req);
        return -1;
    }

    kb_entity_assert_fully(user_profile_entity, abac_req->usr_metadata);

    __destroy_abac_request(abac_req);

    return 0;
}

static struct kb_entity *
__cache_obj_entity(struct nexus_metadata * metadata)
{
    struct kb_entity * entity = nexus_lru_get(cached_obj_entities, &metadata->uuid);

    if (entity) {
        return entity;
    }

    entity = kb_entity_new(&metadata->uuid);

    if (!nexus_lru_put(cached_obj_entities, &entity->uuid, entity)) {
        kb_entity_free(entity);
        log_error("nexus_lru_put() FAILED\n");
        return NULL;
    }

    if (db_assert_kb_entity_type(entity, OBJECT_ATTRIBUTE_TYPE)) {
        log_error("db_assert_kb_entity_type() FAILED\n");
        return NULL;
    }

    return entity;
}

static void
__evict_obj_entity(uintptr_t element, uintptr_t key)
{
    struct kb_entity * entity = (struct kb_entity *)element;

    if (entity->attr_type) {
        db_retract_kb_entity_type(entity);
    }

    kb_entity_free(entity);
}

int
bouncer_init()
{
    if (db_init()) {
        log_error("db_init() FAILED\n");
        return -1;
    }

    // create the necessary structures
    cached_obj_entities = nexus_lru_create(16, __uuid_hasher, __uuid_equals, __evict_obj_entity);

    policy_store_entity = kb_entity_new(abac_policy_store_uuid());

    user_profile_entity = kb_entity_new(&global_user_struct->user_uuid);

    if (__init_user_attributes()) {
        log_error("__init_user_attributes() FAILED\n");
        goto out_err;
    }

    return 0;
out_err:
    nexus_lru_destroy(cached_obj_entities);

    return -1;
}

void
bouncer_destroy()
{
    db_exit();

    if (cached_obj_entities) {
        nexus_lru_destroy(cached_obj_entities);
    }

    if (policy_store_entity) {
        kb_entity_free(policy_store_entity);
    }

    if (user_profile_entity) {
        kb_entity_free(user_profile_entity);
    }
}

bool
bouncer_access_check(struct nexus_metadata * metadata, perm_type_t perm_type)
{
    struct abac_request * abac_req = NULL;

    if (nexus_enclave_is_current_user_owner()) {
        return true;
    }

    abac_req = __create_abac_request(metadata, perm_type);

    if (abac_req == NULL) {
        log_error("__create_abac_request() FAILED\n");
        return -1;
    }

    if (__abac_request_insert_attributes(abac_req)) {
        log_error("__abac_request_insert_attributes() FAILED\n");
        goto out_err;
    }

    if (__abac_request_insert_sysfuncs(abac_req)) {
        log_error("__abac_request_insert_sysfuncs() FAILED\n");
        goto out_err;
    }

    // update the versions of the object and user entitie
    kb_entity_assert_fully(user_profile_entity, abac_req->usr_metadata);
    kb_entity_assert_fully(abac_req->obj_entity, abac_req->obj_metadata);

    if (__abac_request_insert_rules(abac_req)) {
        log_error("__abac_request_insert_rules() FAILED\n");
        goto out_err;
    }

    // query the database
    if (db_ask_permission(perm_type, user_profile_entity, abac_req->obj_entity)) {
        nexus_printf(":( NO\n");
        goto out_err;
    }

    nexus_printf(":) YAY!!!\n");

    __destroy_abac_request(abac_req);

    return false; // TODO change this when done
out_err:
    __destroy_abac_request(abac_req);

    return false;
}

