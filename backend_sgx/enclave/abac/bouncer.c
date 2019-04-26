#include "abac_internal.h"

#include "./datalog-engine/engine.h"

#include "../enclave_internal.h"

#include <libnexus_trusted/nexus_lru.h>
#include <libnexus_trusted/nexus_uuid.h>
#include <libnexus_trusted/hashmap.h>

#include "value.h"


struct __cached_fact {
    struct hashmap_entry hash_entry;
    struct nexus_uuid    uuid;
    char                 name[ATTRIBUTE_NAME_MAX];
    char               * value;
    struct abac_value  * abac_value;
    bool                 is_inserted;
};


/// a cached element points to a user_profile/metadata fact
struct __cached_element {
    struct nexus_uuid uuid;
    char *            uuid_str;

    attribute_type_t  attr_type; // denotes whether _isUser/_isObject have been added

    struct hashmap    attribute_facts;
    struct hashmap    sysfunc_facts;
};


struct abac_request {
    struct policy_store     * policy_store;
    struct attribute_store  * attribute_store;

    struct nexus_metadata   * metadata;
    struct __cached_element * object_element;

    struct user_profile     * user_profile;

    perm_type_t               perm_type;
};


static dl_db_t            my_database;


static struct nexus_lru        * object_elements_map  = NULL;

static struct __cached_element * user_profile_element = NULL;
static struct __cached_element * policy_rules_element = NULL;


static struct __cached_element *
__object_element_upsert(struct nexus_uuid * uuid);


static int
__retract_db_fact(dl_db_t      db,
                  const char * attribute_name,
                  const char * object_name,
                  const char * value);

static int
__assert_db_fact(dl_db_t      db,
                 const char * attribute_name,
                 const char * object_name,
                 const char * value);

static void
__destroy_abac_request(struct abac_request * abac_req);


static struct __cached_fact *
__new_cached_fact(struct nexus_uuid * uuid, char * name, char * value)
{
    struct __cached_fact * new_fact = nexus_malloc(sizeof(struct __cached_fact));

    if (uuid) {
        nexus_uuid_copy(uuid, &new_fact->uuid);
    }

    strncpy(&new_fact->name, name, ATTRIBUTE_NAME_MAX);
    new_fact->value = value;

    return new_fact;
}

static void
__free_cached_fact(struct __cached_fact * cached_fact)
{
    if (cached_fact->value) {
        nexus_free(cached_fact->value);
    }

    if (cached_fact->abac_value) {
        abac_value_free(cached_fact->abac_value);
    }

    nexus_free(cached_fact);
}

static struct __cached_fact *
__put_attribute_fact(struct __cached_element * cached_element,
                     struct nexus_uuid       * uuid,
                     char                    * name,
                     char                    * value)
{
    struct __cached_fact * new_fact = __new_cached_fact(uuid, name, value);

    hashmap_entry_init(new_fact, memhash(&new_fact->uuid, sizeof(struct nexus_uuid)));

    hashmap_add(&cached_element->attribute_facts, &new_fact->hash_entry);

    return new_fact;
}

static struct __cached_fact *
__put_sysfunc_fact(struct __cached_element * cached_element, char * name, char * value)
{
    struct __cached_fact * new_fact = __new_cached_fact(NULL, name, NULL);

    hashmap_entry_init(new_fact, strhash(new_fact->name));

    hashmap_add(&cached_element->sysfunc_facts, &new_fact->hash_entry);

    return new_fact;
}

static struct __cached_fact *
__find_attribute_fact(struct __cached_element * cached_element, struct nexus_uuid * uuid)
{
    struct __cached_fact   tmp_fact = {0};

    nexus_uuid_copy(uuid, &tmp_fact.uuid);
    hashmap_entry_init(&tmp_fact, memhash(&tmp_fact.uuid, sizeof(struct nexus_uuid)));

    return hashmap_get(&cached_element->attribute_facts, &tmp_fact, NULL);
}

static struct __cached_fact *
__find_sysfunc_fact(struct __cached_element * cached_element, char * name)
{
    struct __cached_fact   tmp_fact = {0};

    strncpy(&tmp_fact.name, name, ATTRIBUTE_NAME_MAX);
    hashmap_entry_init(&tmp_fact, strhash(tmp_fact.name));

    return hashmap_get(&cached_element->sysfunc_facts, &tmp_fact, NULL);
}

static int
__attribute_facts_cmp(const void                 * data,
                      const struct __cached_fact * entry1,
                      const struct __cached_fact * entry2,
                      const void                 * keydata)
{
    return nexus_uuid_compare(&entry1->uuid, &entry2->uuid);
}

static int
__sysfunc_facts_cmp(const void                 * data,
                    const struct __cached_fact * entry1,
                    const struct __cached_fact * entry2,
                    const void                 * keydata)
{
    return strncmp(entry1->name, entry2->name, ATTRIBUTE_NAME_MAX);
}

static struct __cached_element *
__new_cached_element(struct nexus_uuid * uuid)
{
    struct __cached_element * cached_element = nexus_malloc(sizeof(struct __cached_element));

    nexus_uuid_copy(uuid, &cached_element->uuid);
    cached_element->uuid_str = nexus_uuid_to_hex(uuid);

    hashmap_init(&cached_element->attribute_facts, (hashmap_cmp_fn)__attribute_facts_cmp, NULL, 17);

    return cached_element;
}

static void
__delete_element_facts(struct __cached_element * cached_element, struct hashmap * facts_map)
{
    struct hashmap_iter iter;

    hashmap_iter_init(facts_map, &iter);

    do {
        struct __cached_fact * cached_fact = hashmap_iter_next(&iter);

        if (cached_fact == NULL) {
            break;
        }

        if (cached_fact->is_inserted) {
            if (__retract_db_fact(my_database,
                                  cached_fact->name,
                                  cached_element->uuid_str,
                                  cached_fact->value)) {
                log_error("__retract_db_fact() FAILED\n");
                continue;
            }
        }

        __free_cached_fact(cached_fact);
    } while (1);

    hashmap_free(facts_map, 0);
}

static void
__free_cached_element(struct __cached_element * cached_element)
{
    __delete_element_facts(cached_element, &cached_element->sysfunc_facts);
    __delete_element_facts(cached_element, &cached_element->attribute_facts);

    nexus_free(cached_element->uuid_str);
    nexus_free(cached_element);
}




static int
__register_fact_with_db(struct __cached_element * cached_element,
                        struct __cached_fact    * cached_fact,
                        char                    * value)
{
    if (cached_fact->is_inserted) {
        if (strncmp(cached_fact->value, value, ATTRIBUTE_VALUE_SIZE) == 0) {
            return 0;
        }

        // retract from datalog engine and update the value
        if (__retract_db_fact(my_database,
                              cached_fact->name,
                              cached_element->uuid_str,
                              cached_fact->value)) {
            log_error("__retract_db_fact() FAILED\n");
            return -1;
        }

        nexus_free(cached_fact->value);
        cached_fact->value = value;
        cached_fact->is_inserted = false;
    }

    if (__assert_db_fact(my_database,
                         cached_fact->name,
                         cached_element->uuid_str,
                         cached_fact->value)) {
        log_error("__assert_db_fact() FAILED\n");
        return -1;
    }

    cached_fact->is_inserted = true;

    return 0;
}

static int
__register_attribute_fact(struct __cached_element * cached_element,
                          struct nexus_uuid       * attr_uuid,
                          char                    * name,
                          char                    * value)
{
    struct __cached_fact * cached_fact = __find_attribute_fact(cached_element, attr_uuid);

    if (cached_fact == NULL) {
        cached_fact = __put_attribute_fact(cached_element, attr_uuid, name, value);
    }

    return __register_fact_with_db(cached_element, cached_fact, value);
}

static int
__register_sysfunc_fact(struct __cached_element * cached_element, char * name, char * value)
{
    struct __cached_fact * cached_fact = __find_sysfunc_fact(cached_element, name);

    if (cached_fact == NULL) {
        cached_fact = __put_sysfunc_fact(cached_element, name, value);
    }

    return __register_fact_with_db(cached_element, cached_fact, value);
}

static int
__assert_cached_element_type(struct __cached_element * cached_element, attribute_type_t attr_type)
{
    if (attr_type == USER_ATTRIBUTE_TYPE) {
        if (__assert_db_fact(my_database, "_isUser", cached_element->uuid_str, NULL)) {
            log_error("could not assert _isUser db_fact\n");
            return -1;
        }
    } else if (attr_type == OBJECT_ATTRIBUTE_TYPE) {
        if (__assert_db_fact(my_database, "_isObject", cached_element->uuid_str, NULL)) {
            log_error("could not assert _isObject db_fact\n");
            return -1;
        }
    } else {
        log_error("unknown attribute type\n");
        return -1;
    }

    cached_element->attr_type = attr_type;

    return 0;
}

static int
__retract_cached_element_type(struct __cached_element * cached_element)
{
    if (cached_element->attr_type == USER_ATTRIBUTE_TYPE) {
        if (__retract_db_fact(my_database, "_isUser", cached_element->uuid_str, NULL)) {
            log_error("could not retract _isUser db_fact\n");
            return -1;
        }
    } else if (cached_element->attr_type == OBJECT_ATTRIBUTE_TYPE) {
        if (__retract_db_fact(my_database, "_isObject", cached_element->uuid_str, NULL)) {
            log_error("could not retract _isObject db_fact\n");
            return -1;
        }
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

static int
__retract_db_fact(dl_db_t      db,
                  const char * attribute_name,
                  const char * object_name,
                  const char * value)
{
    int mark = dl_mark(db);

    if (__insert_db_fact(db, attribute_name, object_name, value)) {
        log_error("__insert_db_fact() FAILED\n");
        goto out_err;
    }

    if (dl_retract(db)) {
        log_error("dl_retract() FAILED\n");
        goto out_err;
    }

    return 0;

out_err:
    dl_reset(db, mark);
    return -1;
}

static int
__assert_db_fact(dl_db_t      db,
                 const char * attribute_name,
                 const char * object_name,
                 const char * value)
{
    int mark = dl_mark(db);

    if (__insert_db_fact(db, attribute_name, object_name, value)) {
        log_error("__insert_db_fact() FAILED\n");
        return -1;
    }

    int ret = dl_assert(db);

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
    dl_reset(db, mark);
    return -1;
}

static int
__insert_attribute_table(struct abac_request     * abac_req,
                         struct __cached_element * cached_element,
                         struct attribute_table  * attribute_table)
{
    struct hashmap_iter iter;
    size_t  skip_count = 0;

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
            skip_count += 1;
            continue;
        }

        if (__register_attribute_fact(cached_element,
                                      &attr_entry->attr_uuid,
                                      attr_term->name,
                                      attr_entry->attr_val)) {
            log_error("could not push attribute pair (%s)\n", attr_term->name);
            return -1;
        }
    } while (1);

    return 0;
}

static int
__insert_system_functions(void                    * user_or_object,
                          struct __cached_element * cached_element,
                          struct nexus_list       * sysfacts_list)
{
    struct nexus_list_iterator * iter = list_iterator_new(sysfacts_list);

    while (list_iterator_is_valid(iter)) {
        struct __sys_func * sys_func = list_iterator_get(iter);

        const char * name      = sys_func_get_name(sys_func);
        char *       new_value = system_function_run(sys_func, user_or_object);

        if (new_value == NULL) {
            // TODO report here
            goto next;
        }

        // get the cached fact and compare its value
        struct __cached_fact * cached_fact = __find_sysfunc_fact(cached_element, (char *)name);

        if (cached_fact && (strncmp(new_value, cached_fact->value, ATTRIBUTE_VALUE_SIZE) == 0)) {
            nexus_free(new_value);
            goto next;
        }

        if (__register_sysfunc_fact(cached_element, (char *)name, new_value)) {
            list_iterator_free(iter);
            log_error("__register_sysfunc_fact() FAILED\n");
            return -1;
        }

next:
        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return 0;
}


static int
__insert_access_sysfuncs(struct abac_request * abac_req)
{
    struct nexus_list * usr_sysfacts = NULL;
    struct nexus_list * obj_sysfacts = NULL;

    int ret = -1;


    usr_sysfacts = system_function_export_sysfuncs(USER_FUNCTION);

    if (__insert_system_functions(abac_req->user_profile, user_profile_element, usr_sysfacts)) {
        log_error("could not insert user system functions\n");
        goto out_err;
    }

    if (abac_req->metadata) {
        obj_sysfacts = system_function_export_sysfuncs(OBJECT_FUNCTION);

        if (__insert_system_functions(abac_req->metadata, abac_req->object_element, obj_sysfacts)) {
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

static int
__insert_access_attributes(struct abac_request * abac_req)
{
    struct attribute_table * user_attr_table = abac_req->user_profile->attribute_table;

    // insert the user_profile attribute table
    if (__insert_attribute_table(abac_req, user_profile_element, user_attr_table)) {
        log_error("could not insert user_profile attribute table into database\n");
        goto out_err;
    }

    // insert the metadata attribute table
    if (abac_req->metadata) {
        struct attribute_table * obj_attr_table = metadata_get_attribute_table(abac_req->metadata);

        if (__insert_attribute_table(abac_req, abac_req->object_element, obj_attr_table)) {
            log_error("could not insert object attribute table into database\n");
            goto out_err;
        }
    }

    return 0;
out_err:
    return -1;
}

static int
__insert_access_rules(struct abac_request * abac_req)
{
    struct nexus_list_iterator * iter = NULL;

    struct __cached_fact * cached_fact = NULL;

    if (abac_req->policy_store->rules_count == 0) {
        return NULL;
    }

    iter = list_iterator_new(&abac_req->policy_store->rules_list);

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        cached_fact = __find_attribute_fact(policy_rules_element, &rule->rule_uuid);

        if (cached_fact == NULL) {
            cached_fact = __put_attribute_fact(policy_rules_element, &rule->rule_uuid, "", NULL);
            if (cached_fact == NULL) {
                log_error("could not cache policy rule\n");
                goto out_err;
            }
        }

        if (cached_fact->is_inserted == false) {
            if (policy_rule_add_to_engine(rule, my_database)) {
                log_error("policy_rule_add_to_engine() FAILED\n");
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

            cached_fact->is_inserted = true;
        }

        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));

    list_iterator_free(iter);

    return 0;
out_err:
    list_iterator_free(iter);

    return -1;
}


static struct abac_request *
__create_abac_request(struct nexus_metadata * metadata, perm_type_t perm_type)
{
    struct abac_request * access_req = nexus_malloc(sizeof(struct abac_request));

    access_req->metadata  = metadata;
    access_req->perm_type = perm_type;

    access_req->policy_store = abac_acquire_policy_store(NEXUS_FREAD);
    if (access_req->policy_store == NULL) {
        log_error("could not acquire policy_store\n");
        return NULL;
    }

    access_req->attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);
    if (access_req->attribute_store == NULL) {
        abac_release_policy_store();
        log_error("could not acquire attribute_store\n");
        return NULL;
    }

    access_req->user_profile = abac_acquire_current_user_profile(NEXUS_FREAD);
    if (access_req->user_profile == NULL) {
        abac_release_policy_store();
        abac_release_attribute_store();
        return NULL;
    }

    if (access_req->metadata) {
        access_req->object_element = __object_element_upsert(&access_req->metadata->uuid);
        if (access_req->object_element == NULL) {
            log_error("__upsert_element() for metadata failed FAILED\n");
            goto out_err;
        }
    }

    return access_req;
out_err:
    __destroy_abac_request(access_req);

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

    if (__assert_cached_element_type(user_profile_element, USER_ATTRIBUTE_TYPE)) {
        log_error("__assert_cached_element_type() FAILED\n");
        return -1;
    }

    if (__insert_access_attributes(abac_req)) {
        log_error("__insert_access_attributes() FAILED\n");
        __destroy_abac_request(abac_req);
        return -1;
    }

    if (__insert_access_sysfuncs(abac_req)) {
        log_error("__insert_access_sysfuncs() FAILED\n");
        __destroy_abac_request(abac_req);
        return -1;
    }

    __destroy_abac_request(abac_req);

    return 0;
}


static struct __cached_element *
__object_element_upsert(struct nexus_uuid * uuid)
{
    struct __cached_element * cached_element = nexus_lru_get(object_elements_map, uuid);

    if (cached_element) {
        return cached_element;
    }

    cached_element = __new_cached_element(uuid);

    if (!nexus_lru_put(object_elements_map, &cached_element->uuid, cached_element)) {
        __free_cached_element(cached_element);
        log_error("nexus_lru_put() FAILED\n");
        return NULL;
    }

    if (__assert_cached_element_type(cached_element, OBJECT_ATTRIBUTE_TYPE)) {
        log_error("__assert_cached_element_type() FAILED\n");
        return -1;
    }

    return cached_element;
}

static void
__object_element_freer(uintptr_t element, uintptr_t key)
{
    struct __cached_element * cached_element = element;

    if (cached_element->attr_type) {
        __retract_cached_element_type(cached_element);
    }

    __free_cached_element(element);
}

int
bouncer_init()
{
    my_database = datalog_engine_create();

    if (my_database == NULL) {
        log_error("could not create a new datalog engine\n");
        return -1;
    }

    // create the necessary structures
    {
        object_elements_map
            = nexus_lru_create(16, __uuid_hasher, __uuid_equals, __object_element_freer);

        policy_rules_element = __new_cached_element(abac_policy_store_uuid());

        user_profile_element = __new_cached_element(&global_user_struct->user_uuid);
    }

    if (__init_user_attributes()) {
        log_error("__init_user_attributes() FAILED\n");
        goto out_err;
    }

    return 0;
out_err:
    nexus_lru_destroy(object_elements_map);

    return -1;
}

void
bouncer_destroy()
{
    if (my_database) {
        datalog_engine_destroy(my_database);
    }

    if (object_elements_map) {
        nexus_lru_destroy(object_elements_map);
    }

    if (policy_rules_element) {
        __free_cached_element(policy_rules_element);
    }

    if (user_profile_element) {
        __free_cached_element(user_profile_element);
    }
}

bool
bouncer_access_check(struct nexus_metadata * metadata, perm_type_t perm_type)
{
    struct abac_request * abac_req = __create_abac_request(metadata, perm_type);

    struct attribute_table * user_attribute_table = NULL;
    struct attribute_table * object_attribute_table = NULL;

    if (abac_req == NULL) {
        log_error("__create_abac_request() FAILED\n");
        return -1;
    }

    if (__insert_access_attributes(abac_req)) {
        log_error("__insert_access_attributes() FAILED\n");
        return -1;
    }

    if (__insert_access_rules(abac_req)) {
        log_error("__insert_access_rules() FAILED\n");
        goto out_err;
    }

    // query the database
    {
        char * permission_string = perm_type_to_string(perm_type);

        if (!datalog_engine_is_true(my_database,
                                    permission_string,
                                    user_profile_element->uuid_str,
                                    abac_req->object_element->uuid_str)) {
            log_error("datalog_engine returned false\n");
            nexus_free(permission_string);
            goto out_err;
        }

        log_error("datalog_engine returned true\n");

        nexus_free(permission_string);
    }

    __destroy_abac_request(abac_req);

    return false;
out_err:
    __destroy_abac_request(abac_req);

    return false;
}

