#include "abac_internal.h"

#include "./datalog-engine/engine.h"

#include "../enclave_internal.h"

#include <libnexus_trusted/nexus_lru.h>
#include <libnexus_trusted/nexus_uuid.h>
#include <libnexus_trusted/hashmap.h>

#include "system_functions.h"

#include "value.h"
#include "db.h"


struct abac_request {
    struct policy_store     * policy_store;
    struct attribute_space  * attribute_space;

    struct nexus_metadata   * obj_metadata;
    struct kb_entity        * obj_entity;

    struct nexus_metadata   * usr_metadata;

    perm_type_t               perm_type;
};


static struct nexus_lru * cached_obj_entities = NULL;

static struct kb_entity * user_profile_entity = NULL;

static struct nexus_list * obj_system_functions = NULL;
static struct nexus_list * usr_system_functions = NULL;

static size_t       policy_store_cached_version = 0;

static void
__destroy_abac_request(struct abac_request * abac_req);

static struct kb_entity *
__cache_obj_entity(struct nexus_metadata * metadata);


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

        const char * name = sys_func_get_name(sys_func);
        char * value = abac_value_stringify(result); // XXX: value/result string optimization

        abac_value_free(result);

        if (db_assert_fact(entity, name, value)) {
            nexus_free(value);
            list_iterator_free(iter);
            log_error("db_assert_fact() FAILED\n");
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

static int
__insert_attribute_table(struct abac_request   * abac_req,
                         struct kb_entity      * entity,
                         struct nexus_metadata * metadata)
{
    struct hashmap_iter iter;

    struct attribute_table * attr_table = metadata_get_attribute_table(metadata);

    hashmap_iter_init(&attr_table->attribute_map, &iter);

    // start iterating the attribute table
    while (1) {
        struct attribute_entry * attr_entry = hashmap_iter_next(&iter);

        if (attr_entry == NULL) {
            break;
        }

        const struct attribute_schema * schema;

        schema = attribute_space_find_uuid(abac_req->attribute_space, &attr_entry->attr_uuid);

        if (schema == NULL) {
            // this could be due to the fact that it has been deleted from attribute store
            // log_error("could not find schema for attribute\n");
            continue;
        }

        if (db_assert_fact(entity, schema->name, attr_entry->attr_val)) {
            log_error("db_assert_fact() FAILED\n");
            return -1;
        }
    }

    return 0;
}

// --]] attributes


static int
__abac_request_insert_facts(struct abac_request   * abac_req,
                            struct kb_entity      * entity,
                            struct nexus_metadata * metadata,
                            struct nexus_list     * sys_functions)
{
    if (metadata->version && metadata->version == entity->metadata_version) {
        return 0;
    }

    if (db_evict_entity(entity)) {
        log_error("could not evict entity\n");
        return -1;
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

    entity->metadata_version = metadata->version;

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

    abac_req->attribute_space = abac_acquire_attribute_space(NEXUS_FREAD);
    if (abac_req->attribute_space == NULL) {
        abac_release_policy_store();
        log_error("could not acquire attribute_space\n");
        return NULL;
    }

    struct user_profile * user_profile = abac_acquire_current_user_profile(NEXUS_FREAD);
    if (user_profile == NULL) {
        abac_release_policy_store();
        abac_release_attribute_space();
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
    abac_release_attribute_space();
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

    db_evict_entity(entity);

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

static int
__audit_abac_request(struct abac_request * abac_req)
{
    struct nexus_metadata * audit_log_metadata = NULL;

    if (db_ask_permission(PERM_AUDIT, user_profile_entity, abac_req->obj_entity)) {
        return 0;
    }

    if (metadata_create_audit_log(abac_req->obj_metadata)) {
        log_error("could not create audit log\n");
        goto out_err;
    }

    audit_log_metadata = metadata_get_audit_log(abac_req->obj_metadata, NEXUS_FRDWR);

    if (audit_log_metadata == NULL) {
        log_error("could not get audit log metadata\n");
        goto out_err;
    }

    if (audit_log_add_event(audit_log_metadata->audit_log,
                            abac_req->perm_type,
                            &global_user_struct->user_uuid,
                            abac_req->obj_metadata->version)) {
        log_error("audit_log_add_event() FAILED\n");
        goto out_err;
    }

    if (nexus_metadata_store(audit_log_metadata)) {
        log_error("nexus_metadata_store() FAILED\n");
        goto out_err;
    }

    if (perm_type_modifies_object(abac_req->perm_type)) {
        abac_req->obj_metadata->audit_log_metadata = audit_log_metadata;
    }

    return 0;
out_err:
    return -1;
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
        goto out_err;
    }

    // 4 - check if there's an audit
    if (__audit_abac_request(abac_req)) {
        log_error("__audit_abac_request() FAAILED\n");
        goto out_err;
    }

    __destroy_abac_request(abac_req);

    return true;
out_err:
    __destroy_abac_request(abac_req);

    return false;
}

// TODO implement max rules
int
bouncer_update_policy_store(struct policy_store * old_policystore,
                            struct policy_store * new_policystore)
{
    if (nexus_enclave_is_current_user_owner()) {
        return 0;
    }

    if (policy_store_cached_version == new_policystore->metadata->version) {
        return 0;
    }

    db_clear_rules();

    // insert the new rules
    {
        struct nexus_list_iterator * iter = list_iterator_new(&new_policystore->rules_list);

        while (list_iterator_is_valid(iter)) {
            struct policy_rule * rule = list_iterator_get(iter);

            if (db_assert_policy_rule(rule)) {
                log_error("db_assert_policy_rule() FAILED\n");
                list_iterator_free(iter);
                return -1;
            }

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }

    return 0;
}


// TODO
int
UNSAFE_bouncer_print_rules()
{
    return -1;
}

int
bounce_remove_from_kb(struct nexus_uuid * uuid)
{
    struct kb_entity * entity = nexus_lru_get(cached_obj_entities, uuid);

    if (entity == NULL) {
        return 0;
    }

    if (db_evict_entity(entity)) {
        log_error("db_evict_entity() FAILED\n");
        return -1;
    }

    return 0;
}
