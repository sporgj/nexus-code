#include "../libnexus_trusted/hashmap.h"

#include "abac_internal.h"

/// each fact entry points to a specific atom's value. The key is a string
/// of the predicate, and the value points to its fact as a value.
struct fact_entry {
    struct hashmap_entry    hash_entry;

    char                    fact[ATTRIBUTE_NAME_MAX];

    char                  * value;
};

struct access_request {
    struct nexus_list       * rules;

    struct hashmap            facts_hashmap;
    size_t                    facts_count;

    struct policy_store     * policy_store;
    struct attribute_store  * attribute_store;

    struct nexus_metadata   * metadata;

    struct user_profile     * user_profile;

    perm_type_t               permission;
};

static int
__attribute_htable_cmp(const void *                   data,
                       const struct attribute_entry * entry1,
                       const struct attribute_entry * entry2,
                       const void *                   keydata)
{
    return nexus_uuid_compare(&entry1->attr_uuid, &entry2->attr_uuid);
}

static struct access_request *
__new_access_request(struct nexus_metadata * metadata, perm_type_t permission)
{
    struct access_request * access_req = nexus_malloc(sizeof(struct access_request));

    access_req->metadata = metadata;
    access_req->permission = permission;

    hashmap_init(&access_req->facts_hashmap, (hashmap_cmp_fn)__attribute_htable_cmp, NULL, 11);

    return access_req;
}

static void
__free_fact_entry(struct fact_entry * entry)
{
    if (entry->value) {
        nexus_free(entry->value);
    }

    nexus_free(entry);
}

static void
__free_access_request(struct access_request * access_req)
{
    struct hashmap_iter iter;

    hashmap_iter_init(&access_req->facts_hashmap, &iter);

    do {
        struct fact_entry * fact_entry = hashmap_iter_next(&iter);

        if (fact_entry == NULL) {
            break;
        }

        __free_fact_entry(fact_entry);
    } while (1);

    hashmap_free(&access_req->facts_hashmap, 0);

    nexus_free(access_req);
}

static void
__put_fact(struct access_request * access_req, char * predicate, char * value)
{
    struct fact_entry * new_fact = nexus_malloc(sizeof(struct fact_entry));

    strncpy(&new_fact->fact, predicate, ATTRIBUTE_NAME_MAX);
    new_fact->value = value;

    hashmap_entry_init(new_fact, strhash(new_fact->fact));

    hashmap_add(&access_req->facts_hashmap, &new_fact->hash_entry);
    access_req->facts_count += 1;
}

static struct fact_entry *
__find_fact(struct access_request * access_req, char * predicate)
{
    struct fact_entry   tmp_fact = {0};
    struct fact_entry * rst_fact = NULL;

    strncpy(&tmp_fact.fact, predicate, ATTRIBUTE_NAME_MAX);

    return hashmap_get(&access_req->facts_hashmap, &tmp_fact, NULL);
}

static const char *
__metadata_attribute_find(struct nexus_metadata * metadata, struct nexus_uuid * attr_uuid)
{
    struct attribute_table * attribute_table = NULL;

    if (metadata->type == NEXUS_DIRNODE) {
        attribute_table = metadata->dirnode->attribute_table;
    } else if (metadata->type == NEXUS_FILENODE) {
        attribute_table = metadata->filenode->attribute_table;
    } else {
        log_error("incorrect metadata type\n");
        return NULL;
    }

    return attribute_table_find(attribute_table, attr_uuid);
}

static int
__extract_attributes(struct access_request * access_req, struct policy_atom * atom)
{
    const char * value = NULL;

    if (__find_fact(access_req, atom->predicate)) {
        // if the fact is already registered, let's skip
        return 0;
    }

    // if we can't find the attribute, the rule is too old
    if (attribute_store_find_uuid(access_req->attribute_store, &atom->attr_uuid) == NULL) {
        // TODO improve error message
        log_error("attribute `%s` could not be found in attribute store\n", atom->predicate);
        return 0;
    }

    if (atom->atom_type == ATOM_TYPE_USER) {
        value = attribute_table_find(access_req->user_profile->attribute_table, &atom->attr_uuid);
    } else {
        value = __metadata_attribute_find(access_req->metadata, &atom->attr_uuid);
    }

    if (value == NULL) {
        // could not find attribute in object
        // XXX: report here
        return 0;
    }

    __put_fact(access_req, atom->predicate, strndup(value, ATTRIBUTE_VALUE_SIZE));

    return 0;
}

static int
__extract_sysfunction(struct access_request * access_req, struct policy_atom * atom)
{
    char * value = NULL;

    if (__find_fact(access_req, atom->predicate)) {
        // if the fact is already registered, let's skip
        return 0;
    }

    if (atom->atom_type = ATOM_TYPE_OBJECT) {
        value = system_function_execute(atom->predicate, OBJECT_FUNCTION, access_req->metadata);
    } else {
        value = system_function_execute(atom->predicate, USER_FUNCTION, access_req->user_profile);
    }

    if (value == NULL) {
        log_error("could not execute system function: `%s`\n", atom->predicate);
        return -1;
    }

    __put_fact(access_req, atom->predicate, value);

    return 0;
}

static int
__process_rule(struct access_request * access_req, struct policy_rule * rule)
{
    struct nexus_list_iterator * iter = list_iterator_new(&rule->atoms);

    int ret = -1;

    do {
        struct policy_atom * atom = list_iterator_get(iter);

        if (atom->pred_type == PREDICATE_ATTR) {
            ret = __extract_attributes(access_req, atom);
        } else {
            ret = __extract_sysfunction(access_req, atom);
        }

        if (ret != 0) {
            goto out_err;
        }

        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));

    list_iterator_free(iter);

    return 0;
out_err:
    list_iterator_free(iter);

    return -1;
}

static int
build_facts(struct access_request * access_req)
{
    struct nexus_list_iterator * iter = list_iterator_new(access_req->rules);

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        if (__process_rule(access_req, rule)) {
            log_error("__process_rule FAILED\n");
            goto out_err;
        }

        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));

    list_iterator_free(iter);

    return 0;
out_err:
    list_iterator_free(iter);

    return -1;
}

static char *
build_datalog_program(struct access_request * access_req)
{
    // TODO
    return NULL;
}

bool
access_check(struct nexus_metadata * metadata, perm_type_t permission)
{
    struct access_request * access_req = __new_access_request(metadata, permission);

    char * datalog_program = NULL;

    access_req->policy_store = abac_acquire_policy_store(NEXUS_FREAD);
    if (access_req->policy_store == NULL) {
        log_error("could not acquire policy_store\n");
        goto out_exit;
    }

    access_req->attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);
    if (access_req->attribute_store == NULL) {
        abac_release_policy_store();
        log_error("could not acquire attribute_store\n");
        goto out_exit;
    }

    access_req->user_profile = abac_global_get_current_usertable(NEXUS_FREAD);
    if (access_req->user_profile == NULL) {
        abac_release_policy_store();
        abac_release_attribute_store();
        goto out_exit;
    }

    access_req->rules = policy_store_select_rules(permission);
    if (access_req->rules == NULL) {
        // no policies will allow this
        goto out_err;
    }


    datalog_program = build_datalog_program(access_req);

    if (datalog_program == NULL) {
        log_error("build_datalog_program() FAILED\n");
        goto out_err;
    }

    abac_release_policy_store();
    abac_release_attribute_store();
    abac_global_put_current_usertable();

    __free_access_request(access_req);

    return true;

out_err:
    abac_release_policy_store();
    abac_release_attribute_store();
    abac_global_put_current_usertable();

out_exit:
    __free_access_request(access_req);

    return false;
}
