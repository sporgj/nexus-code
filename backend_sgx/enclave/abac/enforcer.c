#include "../libnexus_trusted/hashmap.h"

#include "../enclave_internal.h"

#include "abac_internal.h"
#include "policy_store.h"
#include "attribute_store.h"
#include "system_functions.h"
#include "atom.h"

struct computed_fact {
    struct hashmap_entry    hash_entry;

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

static void
__free_fact(struct computed_fact * entry)
{
    if (entry->value) {
        nexus_free(entry->value);
    }

    nexus_free(entry);
}

static void
__put_fact(struct access_request * access_req, char * value)
{
    struct computed_fact * new_fact = nexus_malloc(sizeof(struct computed_fact));

    new_fact->value = value;

    hashmap_entry_init(new_fact, strhash(new_fact->value));

    hashmap_add(&access_req->facts_hashmap, &new_fact->hash_entry);
    access_req->facts_count += 1;
}

static struct computed_fact *
__find_fact(struct access_request * access_req, char * value)
{
    struct computed_fact   tmp_fact = {0};
    struct computed_fact * rst_fact = NULL;

    tmp_fact.value = value;
    hashmap_entry_init(&tmp_fact, strhash(tmp_fact.value));

    return hashmap_get(&access_req->facts_hashmap, &tmp_fact, NULL);
}

static int
__facts_hashmap_cmp(const void                 * data,
                    const struct computed_fact * entry1,
                    const struct computed_fact * entry2,
                    const void                 * keydata)
{
    return strcmp(entry1->value, entry2->value);
}

static struct access_request *
__new_access_request(struct nexus_metadata * metadata, perm_type_t permission)
{
    struct access_request * access_req = nexus_malloc(sizeof(struct access_request));

    access_req->metadata = metadata;
    access_req->permission = permission;

    hashmap_init(&access_req->facts_hashmap, (hashmap_cmp_fn)__facts_hashmap_cmp, NULL, 11);

    return access_req;
}

static void
__free_access_request(struct access_request * access_req)
{
    struct hashmap_iter iter;

    hashmap_iter_init(&access_req->facts_hashmap, &iter);

    do {
        struct computed_fact * fact_entry = hashmap_iter_next(&iter);

        if (fact_entry == NULL) {
            break;
        }

        __free_fact(fact_entry);
    } while (1);

    hashmap_free(&access_req->facts_hashmap, 0);

    nexus_free(access_req);
}

static struct abac_value *
__execute_attribute(struct access_request * access_req,
                    char                  * name,
                    atom_type_t             atom_type)
{
    struct attribute_table * attribute_table = NULL;
    struct attribute_term  * attribute_term  = NULL;

    const char * value;


    attribute_term = attribute_store_find_name(access_req->attribute_store, name);
    if (attribute_term == NULL) {
        return NULL;
    }

    if (atom_type == ATOM_TYPE_OBJECT) {
        attribute_table = metadata_get_attribute_table(access_req->metadata);
        value           = attribute_table_find(attribute_table, &attribute_term->uuid);
    } else if (atom_type == ATOM_TYPE_USER) {
        attribute_table = access_req->user_profile->attribute_table;
        value           = attribute_table_find(attribute_table, &attribute_term->uuid);
    } else {
        log_error("unknown atom type\n");
        return NULL;
    }

    if (value == NULL) {
        return NULL;
    }

    return abac_value_from_str(value);
}

static struct abac_value *
__execute_sysfunction(struct access_request * access_req,
                      char                  * function_str,
                      atom_type_t             atom_type)
{
    if (atom_type == ATOM_TYPE_OBJECT) {
        return system_function_execute(function_str, OBJECT_FUNCTION, access_req->metadata);
    } else if (atom_type == ATOM_TYPE_USER) {
        return system_function_execute(function_str, USER_FUNCTION, access_req->user_profile);
    }

    log_error("could not execute system function: `%s`\n", function_str);

    return NULL;
}

static struct abac_value *
__get_arg_operand(struct access_request * access_req, const struct atom_argument * atom_arg)
{
    struct abac_value * abac_value = atom_arg->abac_value;

    switch (abac_value->type) {
    case ABAC_VALUE_STRING:
    case ABAC_VALUE_NUMBER:
        return abac_value_shallow_copy(atom_arg->abac_value);
    case ABAC_VALUE_IDENTIFIER:
        goto abac_identifier;
    default:
        log_error("unknown atom argument type\n");
        return NULL;
    }


abac_identifier:
    {
        char * symbol = atom_argument_string_val(atom_arg);

        atom_type_t atom_type = atom_type_from_char(symbol[0]);
        if (atom_type == ATOM_TYPE_NONE) {
            log_error("could not derive atom type from argument\n");
            return NULL;
        }

        if (symbol[2] == '@') {
            // we are running a system function
            return __execute_sysfunction(access_req, &symbol[2], atom_type);
        } else {
            return __execute_attribute(access_req, &symbol[2], atom_type);
        }
    }

    return NULL;
}

/// gets the arguments from the atom, runs sys functions on object/user, then run bool operator
static int
__extract_booloperator(struct access_request * access_req, struct policy_atom * atom)
{
    const struct atom_argument * left_arg = policy_atom_get_arg(atom, 0);
    const struct atom_argument * right_arg = policy_atom_get_arg(atom, 1);

    struct abac_value * left_operand = __get_arg_operand(access_req, left_arg);
    struct abac_value * right_operand = __get_arg_operand(access_req, right_arg);

    bool eval_true = false;

    if ((left_operand == NULL) || (right_operand == NULL)) {
        log_error("could not get operands for boolean operator\n");
        goto out_err;
    }

    if (boolean_operator_execute(atom->predicate, left_operand, right_operand, &eval_true)) {
        log_error("could not execute boolean operator `%s`\n", atom->predicate);
        goto out_err;
    }


    // add it as a fact
    if (eval_true) {
        char * atom_str = policy_atom_to_str(atom, false);
        if (atom_str == NULL) {
            log_error("policy_atom_to_str() FAILED\n");
            goto out_err;
        }

        __put_fact(access_req, atom_str);
    }

    abac_value_free(left_operand);
    abac_value_free(right_operand);

    return 0;
out_err:
    if (left_operand) {
        abac_value_free(left_operand);
    }

    if (right_operand) {
        abac_value_free(right_operand);
    }

    return -1;
}

static int
__process_rule(struct access_request * access_req, struct policy_rule * rule)
{
    struct nexus_list_iterator * iter = list_iterator_new(&rule->atoms);

    do {
        struct policy_atom * atom = list_iterator_get(iter);

#if 0
        if (atom->pred_type == PREDICATE_BOOL) {
            if (__extract_booloperator(access_req, atom)) {
                log_error("could not process boolean operator\n");
                list_iterator_free(iter);
                return -1;
            }
        }
#endif

        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));

    list_iterator_free(iter);

    return 0;
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

static int
__datalog_facts_stored(struct access_request * access_req, rapidstring * string_builder)
{
    struct hashmap_iter iter;

    hashmap_iter_init(&access_req->facts_hashmap, &iter);

    do {
        struct computed_fact * fact_entry = hashmap_iter_next(&iter);

        if (fact_entry == NULL) {
            return 0;
        }

        rs_cat(string_builder, fact_entry->value);
        rs_cat_n(string_builder, ".\n", 2);

    } while(1);

    return 0;
}

static int
__datalog_facts(struct access_request * access_req, rapidstring * string_builder)
{
    struct attribute_table * user_attr_table   = access_req->user_profile->attribute_table;
    struct attribute_table * obj_attr_table = metadata_get_attribute_table(access_req->metadata);

    size_t user_attributes_skipped   = 0;
    size_t object_attributes_skipped = 0;

    if (attribute_table_export_facts(user_attr_table,
                                     access_req->attribute_store,
                                     "u",
                                     string_builder,
                                     &user_attributes_skipped)) {
        log_error("could not export user facts\n");
        return -1;
    }

    if (attribute_table_export_facts(obj_attr_table,
                                     access_req->attribute_store,
                                     "o",
                                     string_builder,
                                     &object_attributes_skipped)) {
        log_error("could not export object facts\n");
        return -1;
    }

    if (system_function_export_facts(global_user_struct, USER_FUNCTION, string_builder)) {
        log_error("could not export user system function facts\n");
        return -1;
    }

    if (system_function_export_facts(access_req->metadata, OBJECT_FUNCTION, string_builder)) {
        log_error("could not export object system function facts\n");
        return -1;
    }

    if (user_attributes_skipped || object_attributes_skipped) {
        // TODO handle reporting
    }

    if (__datalog_facts_stored(access_req, string_builder)) {
        log_error("__datalog_facts_stored() FAILED\n");
        return -1;
    }

    rs_cat(string_builder, "_dummy(u).\n_dummy(o).\n");

    return 0;
}

static int
__datalog_queries(struct access_request * access_req, rapidstring * string_builder)
{
    struct nexus_list_iterator * iter = list_iterator_new(access_req->rules);

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        rs_cat(string_builder, "\n");

        if (__policy_rule_datalog_string(rule, string_builder)) {
            log_error("could not generate rule datalog\n");
            list_iterator_free(iter);
            return -1;
        }

        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));

    list_iterator_free(iter);

    return 0;
}

static char *
build_datalog_program(struct access_request * access_req)
{
    char      * datalog_program = NULL;

    rapidstring string_builder;

    rs_init(&string_builder);

    if (__datalog_facts(access_req, &string_builder)) {
        log_error("__datalog_facts() FAILED\n");
        goto out_err;
    }

    if (__datalog_queries(access_req, &string_builder)) {
        log_error("__datalog_queries() FAILED\n");
        goto out_err;
    }

    rs_cat(&string_builder, "\n");

    if (__permission_type_to_datalog(access_req->permission, &string_builder, false)) {
        log_error("__permission_type_to_datalog() FAILED\n");
        goto out_err;
    }

    rs_cat(&string_builder, "?\n");

    datalog_program = strndup(rs_data_c(&string_builder), rs_len(&string_builder));
    rs_free(&string_builder);

    return datalog_program;
out_err:
    rs_free(&string_builder);
    return NULL;
}

bool
nexus_abac_access_check(struct nexus_metadata * metadata, perm_type_t permission)
{
    struct access_request * access_req      = NULL;

    char                  * datalog_program = NULL;

    char                  * datalog_answer  = NULL;

    if (nexus_enclave_is_current_user_owner()) {
        return true;
    }


    access_req = __new_access_request(metadata, permission);
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

    access_req->user_profile = abac_acquire_current_user_profile(NEXUS_FREAD);
    if (access_req->user_profile == NULL) {
        abac_release_policy_store();
        abac_release_attribute_store();
        goto out_exit;
    }

    access_req->rules = policy_store_select_rules(access_req->policy_store, permission);
    if (access_req->rules == NULL) {
        goto out_err;
    }

    if (build_facts(access_req)) {
        log_error("build_facts() FAILED\n");
        goto out_err;
    }

    datalog_program = build_datalog_program(access_req);

    if (datalog_program == NULL) {
        log_error("build_datalog_program() FAILED\n");
        goto out_err;
    }

    nexus_printf("==================\n");
    nexus_printf("%s", datalog_program);
    nexus_printf("------------------\n");

#if 0
    if (datalog_evaluate(datalog_program, &datalog_answer)) {
        log_error("datalog_evaluate() FAILED\n");
        goto out_err;
    }

    nexus_printf("%s\n", datalog_answer);
    nexus_printf("==================\n\n");
#endif


    nexus_free(datalog_program);
    nexus_free(datalog_answer);


    abac_release_policy_store();
    abac_release_attribute_store();
    abac_release_current_user_profile();

    __free_access_request(access_req);

    return false;

out_err:
    abac_release_policy_store();
    abac_release_attribute_store();
    abac_release_current_user_profile();

    if (datalog_program) {
        nexus_free(datalog_program);
    }

    if (datalog_answer) {
        nexus_free(datalog_answer);
    }
out_exit:
    __free_access_request(access_req);

    return false;
}
