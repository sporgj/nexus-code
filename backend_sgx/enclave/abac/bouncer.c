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

static struct nexus_list * obj_system_functions = NULL;
static struct nexus_list * usr_system_functions = NULL;

static void
__destroy_abac_request(struct abac_request * abac_req);

static struct kb_entity *
__cache_obj_entity(struct nexus_metadata * metadata);



static int
__register_fact(struct kb_entity * entity,
                struct kb_fact   * cached_fact,
                const char       * value,
                size_t             generation)
{
    if (cached_fact->generation == generation) {
        db_reaffirm_fact(cached_fact);
        return 0;
    }

    if (cached_fact->is_inserted) {
        if (strncmp(cached_fact->value, value, ATTRIBUTE_VALUE_SIZE) == 0) {
            db_reaffirm_fact(cached_fact);
            goto out_success;
        }

        // retract from datalog engine and update the value
        if (db_retract_fact(cached_fact)) {
            log_error("db_retract_fact() FAILED\n");
            return -1;
        }

        kb_fact_update_value(cached_fact, value);
    }

    if (db_assert_fact(cached_fact)) {
        log_error("db_retract_fact() FAILED\n");
        return -1;
    }

out_success:
    cached_fact->generation = generation;

    return 0;
}


// --[[ system facts

static int
__insert_system_functions(struct nexus_metadata * metadata,
                          struct kb_entity      * entity,
                          struct nexus_list     * sysfacts_list)
{
    struct nexus_list_iterator * iter = list_iterator_new(sysfacts_list);

    while (list_iterator_is_valid(iter)) {
        struct __sys_func * sys_func = list_iterator_get(iter);

        struct abac_value * result   = system_function_run(sys_func, metadata);

        if (result == NULL) {
            goto next;
        }

        char * value = abac_value_stringify(result);

        abac_value_free(result);


        const char * name = sys_func_get_name(sys_func);

        struct kb_fact * cached_fact = kb_entity_find_name_fact(entity, (char *)name);

        if (cached_fact == NULL) {
            cached_fact = kb_entity_put_name_fact(entity, (char *)name, value);
        }

        if (__register_fact(entity, cached_fact, value, metadata->version)) {
            nexus_free(value);
            list_iterator_free(iter);
            log_error("__register_fact() FAILED\n");
            return -1;
        }

        nexus_free(value);
next:
        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return 0;
}

// --]] system facts


// --[[ attributes

static inline struct kb_fact *
__new_attribute_fact(struct abac_request    * abac_req,
                     struct kb_entity       * entity,
                     struct attribute_entry * attr_entry)
{
    const struct attribute_term * attr_term;

    attr_term = attribute_store_find_uuid(abac_req->attribute_store, &attr_entry->attr_uuid);

    if (attr_term == NULL) {
        // TODO maybe report here?
        return NULL;
    }

    return kb_entity_put_uuid_fact(entity,
                                   &attr_entry->attr_uuid,
                                   (char *)attr_term->name,
                                   attr_entry->attr_val);
}

static int
__insert_attribute_table(struct abac_request   * abac_req,
                         struct kb_entity      * entity,
                         struct nexus_metadata * metadata)
{
    struct hashmap_iter iter;

    struct attribute_table * attr_table = metadata_get_attribute_table(metadata);

    if (!kb_entity_needs_refresh(entity, metadata)) {
        return 0;
    }

    if (attr_table->generation == entity->attribute_table_generation) {
        return 0;
    }

    hashmap_iter_init(&attr_table->attribute_map, &iter);

    // start iterating the attribute table
    while (1) {
        struct attribute_entry * attr_entry = hashmap_iter_next(&iter);

        if (attr_entry == NULL) {
            break;
        }

        struct kb_fact * cached_fact = kb_entity_find_uuid_fact(entity, &attr_entry->attr_uuid);

        if (cached_fact == NULL) {
            cached_fact = __new_attribute_fact(abac_req, entity, attr_entry);
        }

        if (__register_fact(entity, cached_fact, attr_entry->attr_val, attr_table->generation)) {
            log_error("__register_fact() FAILED\n");
            return -1;
        }

        cached_fact->generation = attr_table->generation;
    }

    // TODO retract the facts that are not suppose to be in the database
    // pop out the deleted rules
    {
        struct list_head * curr = NULL;
        struct list_head * next = NULL;

        list_for_each_prev_safe(curr, next, &entity->uuid_facts_lru) {
            struct kb_fact * cached_fact = __kb_fact_from_entity_list(curr);

            if ((cached_fact->generation >= attr_table->generation)) {
                // XXX: we should probably stop here
                continue;
            }

            if (db_retract_fact(cached_fact)) {
                log_error("db_retract_policy_rule() FAILED\n");
                continue;
            }

            kb_entity_del_uuid_fact(entity, cached_fact);
        }
    }

    entity->attribute_table_generation = attr_table->generation;

    return 0;
}

// --]] attributes


static int
__abac_request_insert_facts(struct abac_request   * abac_req,
                            struct kb_entity      * entity,
                            struct nexus_metadata * metadata,
                            struct nexus_list     * sys_functions)
{
    if (!kb_entity_needs_refresh(entity, metadata)) {
        return 0;
    }

    // insert the type
    if (db_assert_kb_entity_type(entity)) {
        log_error("db_assert_kb_entity_type() FAILED\n");
        return -1;
    }

    // insert the system functions
    if (__insert_system_functions(metadata, entity, sys_functions)) {
        log_error("__insert_system_functions() FAILED\n");
        goto out_err;
    }

    // insert the attributes
    if (__insert_attribute_table(abac_req, entity, metadata)) {
        log_error("__insert_attribute_table() FAILED\n");
        goto out_err;
    }

    kb_entity_assert_fully(entity, metadata);

    return 0;
out_err:
    return -1;
}

static struct abac_request *
__create_abac_request(struct nexus_metadata * metadata, perm_type_t perm_type)
{
    struct abac_request * abac_req = nexus_malloc(sizeof(struct abac_request));

    abac_req->obj_metadata = metadata;
    abac_req->perm_type    = perm_type;

    abac_req->policy_store = abac_refresh_bouncer_policy_store();
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
    struct abac_request * abac_req = __create_abac_request(NULL, PERM_READ);

    if (abac_req == NULL) {
        log_error("__create_abac_request() FAILED\n");
        return -1;
    }

    if (__abac_request_insert_facts(abac_req,
                                    user_profile_entity,
                                    abac_req->usr_metadata,
                                    usr_system_functions)) {
        log_error("__abac_request_insert_facts() FAILED\n");
        __destroy_abac_request(abac_req);
        return -1;
    }

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

    entity = kb_entity_new(&metadata->uuid, OBJECT_ATTRIBUTE_TYPE);

    if (!nexus_lru_put(cached_obj_entities, &entity->uuid, entity)) {
        kb_entity_free(entity);
        log_error("nexus_lru_put() FAILED\n");
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
    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    if (db_init()) {
        log_error("db_init() FAILED\n");
        return -1;
    }

    // create the necessary structures
    cached_obj_entities = nexus_lru_create(16, __uuid_hasher, __uuid_equals, __evict_obj_entity);

    policy_store_entity = kb_entity_new(abac_policy_store_uuid(), UNKNOWN_ATTRIBUTE_TYPE);

    user_profile_entity = kb_entity_new(&global_user_struct->user_uuid, USER_ATTRIBUTE_TYPE);

    obj_system_functions = system_function_export_sysfuncs(OBJECT_FUNCTION);
    usr_system_functions = system_function_export_sysfuncs(USER_FUNCTION);

    if (__init_user_attributes()) {
        log_error("__init_user_attributes() FAILED\n");
        goto out_err;
    }

    return 0;
out_err:
    bouncer_destroy();

    return -1;
}

void
bouncer_destroy()
{
    if (nexus_enclave_is_current_user_owner()) {
        return;
    }

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

    if (obj_system_functions) {
        nexus_list_destroy(obj_system_functions);
        nexus_free(obj_system_functions);
    }

    if (usr_system_functions) {
        nexus_list_destroy(usr_system_functions);
        nexus_free(usr_system_functions);
    }
}

bool
bouncer_access_check(struct nexus_metadata * metadata, perm_type_t perm_type)
{
    if (nexus_enclave_is_current_user_owner()) {
        return true;
    }

    struct abac_request * abac_req = __create_abac_request(metadata, perm_type);

    if (abac_req == NULL) {
        log_error("__create_abac_request() FAILED\n");
        return -1;
    }

    // 1 - insert the user profile facts
    if (__abac_request_insert_facts(abac_req,
                                    user_profile_entity,
                                    abac_req->usr_metadata,
                                    usr_system_functions)) {
        log_error("__abac_request_insert_facts() user metadata FAILED\n");
        goto out_err;
    }

    // 2 - insert the object facts
    if (__abac_request_insert_facts(abac_req,
                                    abac_req->obj_entity,
                                    abac_req->obj_metadata,
                                    obj_system_functions)) {
        log_error("__abac_request_insert_facts() object metadata FAILED\n");
        goto out_err;
    }

    // 3 - query the database
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

static int
__insert_policy_rule(struct policy_store * policy_store, struct policy_rule * rule)
{
    struct kb_fact * cached_fact = kb_entity_find_uuid_fact(policy_store_entity, &rule->rule_uuid);

    // we assume all rules are always inserted
    if (cached_fact) {
        goto out_success;
    }

    cached_fact = kb_entity_put_uuid_fact(policy_store_entity, &rule->rule_uuid, "", NULL);

    if (cached_fact == NULL) {
        log_error("could not cache policy rule\n");
        goto out_err;
    }

    cached_fact->is_rule = true;

    if (db_assert_policy_rule(rule)) {
        log_error("db_assert_policy_rule() FAILED\n");
        goto out_err;
    }

    cached_fact->is_inserted = true;

out_success:
    cached_fact->rule_ptr   = rule;
    cached_fact->generation = policy_store->metadata->version;

    // move it to the front
    list_move(&cached_fact->entity_lru, &policy_store_entity->uuid_facts_lru);
    return 0;

out_err:
    return -1;
}

int
bouncer_update_policy_store(struct policy_store * old_policystore,
                            struct policy_store * new_policystore)
{
    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    if (policy_store_entity->metadata_version == new_policystore->metadata->version) {
        return 0;
    }

    // insert the new rules
    {
        struct nexus_list_iterator * iter = list_iterator_new(&new_policystore->rules_list);

        while (list_iterator_is_valid(iter)) {
            struct policy_rule * rule = list_iterator_get(iter);

            // try inserting the rul
            if (__insert_policy_rule(new_policystore, rule)) {
                log_error("__insert_policy_rule() FAILED\n");
                list_iterator_free(iter);
                return -1;
            }

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }

    // pop out the deleted rules
    {
        struct list_head * curr = NULL;
        struct list_head * next = NULL;

        list_for_each_prev_safe(curr, next, &policy_store_entity->uuid_facts_lru) {
            struct kb_fact * cached_fact_rule = __kb_fact_from_entity_list(curr);

            if ((cached_fact_rule->generation >= new_policystore->metadata->version)) {
                // XXX: we should probably stop here
                continue;
            }

            if (db_retract_policy_rule(cached_fact_rule->rule_ptr)) {
                log_error("db_retract_policy_rule() FAILED\n");
                return -1;
            }

            kb_entity_del_uuid_fact(policy_store_entity, cached_fact_rule);
        }
    }

    policy_store_entity->metadata_version = new_policystore->metadata->version;
    policy_store_entity->is_fully_asserted = true;

    return 0;
}


int
UNSAFE_bouncer_print_rules()
{
    rapidstring string_builder;

    struct list_head * curr = NULL;

    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }


    rs_init(&string_builder);

    {
        char tmp_buffer[64] = { 0 };

        snprintf(tmp_buffer, sizeof(tmp_buffer), "%zu Rules", policy_store_entity->uuid_facts_count);
        rs_cat(&string_builder, tmp_buffer);

        rs_cat(&string_builder, "\n-----------\n");
    }


    list_for_each(curr, &policy_store_entity->uuid_facts_lru) {
        struct kb_fact * cached_fact = __kb_fact_from_entity_list(curr);

        if (__policy_rule_datalog_string(cached_fact->rule_ptr, &string_builder)) {
            log_error("__policy_rule_datalog_string() FAILED\n");
            goto out_err;
        }

        rs_cat_n(&string_builder, "\n", 1);
    }

    ocall_print(rs_data_c(&string_builder));

    rs_free(&string_builder);

    return 0;
out_err:
    rs_free(&string_builder);

    return -1;
}
