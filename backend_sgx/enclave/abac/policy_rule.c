#include "abac_internal.h"
#include "policy_rule.h"

#include "../libnexus_trusted/nexus_str.h"
#include "../libnexus_trusted/rapidstring.h"


struct __policy_rule_hdr {
    perm_type_t             perm_type;

    uint16_t                atom_count;

    struct nexus_uuid       rule_uuid;
} __attribute__((packed));

struct __policy_atom_buf {
    atom_type_t             atom_type;
    pred_type_t             pred_type;

    struct nexus_uuid       attr_uuid; // 0s when not an attribute
    char                    predicate[SYSTEM_FUNC_MAX_LENGTH];

    size_t                  arity;

    size_t                  args_bufsize;

    uint8_t                 args_buffer[0];
} __attribute__((packed));



static uint8_t *
policy_atom_to_buf(struct policy_atom * atom, uint8_t * buffer, size_t buflen);

struct policy_atom *
policy_atom_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_ptr);

static int
__policy_atom_to_str(struct policy_atom * atom, rapidstring * string_builder);



// --[[ policy atom

static void
__free_nexus_str(void * el)
{
    struct nexus_string * nexus_str = (struct nexus_string *)el;

    nexus_free(nexus_str);
}

struct policy_atom *
policy_atom_new()
{
    struct policy_atom * atom = nexus_malloc(sizeof(struct policy_atom));

    nexus_list_init(&atom->args_list);
    nexus_list_set_deallocator(&atom->args_list, __free_nexus_str);

    return atom;
}

struct policy_atom *
policy_atom_new_from_predicate(char * predicate)
{
    struct policy_atom * atom = policy_atom_new();
    policy_atom_set_predicate(atom, predicate);

    return atom;
}

void
policy_atom_free(struct policy_atom * atom)
{
    nexus_list_destroy(&atom->args_list);
    nexus_free(atom);
}

size_t
policy_atom_buf_size(struct policy_atom * atom)
{
    return sizeof(struct __policy_atom_buf) + atom->args_bufsize;
}

static int
__policy_atom_to_str(struct policy_atom * atom, rapidstring * string_builder)
{
    rs_cat(string_builder, atom->predicate);
    rs_cat(string_builder, "(");

    if (atom->atom_type == ATOM_TYPE_USER) {
        rs_cat(string_builder, "U");
    } else if (atom->atom_type == ATOM_TYPE_OBJECT) {
        rs_cat(string_builder, "O");
    } else {
        log_error("atom type should be object or user\n");
        goto out_err;
    }

    // we only have 1 argument
    if (atom->arity) {
        struct nexus_string * nexus_str = nexus_list_get(&atom->args_list, 0);

        if (nexus_str == NULL) {
            log_error("could not get nexus_string in atom\n");
            goto out_err;
        }

        rs_cat(string_builder, ", \"");
        rs_cat(string_builder, &nexus_str->_str);
        rs_cat(string_builder, "\"");
    }

    rs_cat(string_builder, ")");

    return 0;
out_err:
    return -1;
}

char *
policy_atom_to_str(struct policy_atom * atom)
{
    char *      result_string = NULL;
    rapidstring string_builder;

    // "10" is arbirtrary, it's my estimate for spacing and commas
    rs_init_w_cap(&string_builder, policy_atom_buf_size(atom) + 10);

    if (__policy_atom_to_str(atom, &string_builder)) {
        log_error("__policy_atom_to_str() FAILED\n");
        rs_free(&string_builder);
        return NULL;
    }

    result_string = strndup(rs_data_c(&string_builder), rs_len(&string_builder));
    rs_free(&string_builder);

    return result_string;
}

static uint8_t *
policy_atom_to_buf(struct policy_atom * atom, uint8_t * buffer, size_t buflen)
{
    struct __policy_atom_buf * atom_buffer   = (struct __policy_atom_buf *)buffer;

    size_t                     atom_buf_size = policy_atom_buf_size(atom);

    uint8_t                  * output_ptr    = NULL;
    size_t                     output_len    = 0;


    if (atom_buf_size > buflen) {
        log_error("buffer is too small to store atom\n");
        return NULL;
    }

    // serialize the header
    {
        atom_buffer->atom_type    = atom->atom_type;
        atom_buffer->pred_type    = atom->pred_type;

        atom_buffer->arity        = atom->arity;
        atom_buffer->args_bufsize = atom->args_bufsize;

        nexus_uuid_copy(&atom->attr_uuid, &atom_buffer->attr_uuid);
        memcpy(atom_buffer->predicate, atom->predicate, SYSTEM_FUNC_MAX_LENGTH);
    }

    // initialize the output_ptr and output_len
    output_ptr = (buffer + sizeof(struct __policy_atom_buf));
    output_len = (buflen - sizeof(struct __policy_atom_buf));

    {
        struct nexus_list_iterator * iter = list_iterator_new(&atom->args_list);

        while (list_iterator_is_valid(iter)) {
            struct nexus_string * nexus_str = list_iterator_get(iter);

            uint8_t * next_ptr = nexus_string_to_buf(nexus_str, output_ptr, output_len);

            if (next_ptr == NULL) {
                log_error("nexus_string_to_buf() FAILED\n");
                list_iterator_free(iter);
                return NULL;
            }

            output_len -= (uintptr_t)(next_ptr - output_ptr);
            output_ptr = next_ptr;

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }

    // make sure that the output_ptr is at the endof the buffer
    if (output_ptr != (buffer + atom_buf_size)) {
        log_error("the output_ptr is not at the end of the buffer\n");
        return NULL;
    }

    return (buffer + atom_buf_size);
}

struct policy_atom *
policy_atom_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_ptr)
{
    struct __policy_atom_buf * tmp_atom_buf = (struct __policy_atom_buf *)buffer;

    struct policy_atom       * new_policy_atom = NULL;

    size_t total_size = sizeof(struct __policy_atom_buf) + tmp_atom_buf->args_bufsize;

    if (buflen < total_size) {
        log_error("the atom buffer is too small. buflen=%zu, atom_bufsize=%zu\n",
                  buflen,
                  total_size);
        return NULL;
    }

    new_policy_atom = policy_atom_new();

    // parse the header
    {
        new_policy_atom->atom_type = tmp_atom_buf->atom_type;
        new_policy_atom->pred_type = tmp_atom_buf->pred_type;

        new_policy_atom->arity        = tmp_atom_buf->arity;
        new_policy_atom->args_bufsize = tmp_atom_buf->args_bufsize;

        nexus_uuid_copy(&tmp_atom_buf->attr_uuid, &new_policy_atom->attr_uuid);
        memcpy(new_policy_atom->predicate, tmp_atom_buf->predicate, SYSTEM_FUNC_MAX_LENGTH);
    }

    // set the output_ptr to the start of the buffer
    *output_ptr = tmp_atom_buf->args_buffer;

    // parse the args buffer
    {
        uint8_t             * next_ptr = tmp_atom_buf->args_buffer;
        struct nexus_string * nexus_str = NULL;

        for (size_t i = 0; i < tmp_atom_buf->arity; i++) {
            nexus_str = nexus_string_from_buf(next_ptr, buflen, output_ptr);
            nexus_list_append(&new_policy_atom->args_list, nexus_str);

            next_ptr = *output_ptr;
        }
    }

    if (*output_ptr != (buffer + total_size)) {
        log_error("output_ptr is not at the end of read buffer\n");
        policy_atom_free(new_policy_atom);
        return NULL;
    }

    return new_policy_atom;
}

int
policy_atom_push_arg(struct policy_atom * atom, char * str)
{
    struct nexus_string * nexus_str = nexus_string_from_str(str);

    nexus_list_append(&atom->args_list, nexus_str);

    atom->arity        += 1;
    atom->args_bufsize += nexus_string_buf_size(nexus_str);

    return 0;
}


void
policy_atom_set_uuid(struct policy_atom * atom, struct nexus_uuid * uuid)
{
    nexus_uuid_copy(uuid, &atom->attr_uuid);
}

void
policy_atom_set_predicate(struct policy_atom * atom, char * predicate_str)
{
    memset(&atom->predicate, 0, SYSTEM_FUNC_MAX_LENGTH);
    strncpy(&atom->predicate, predicate_str, SYSTEM_FUNC_MAX_LENGTH);

    if (atom->predicate[0] == '@') {
        atom->pred_type = PREDICATE_FUNC;
    } else {
        atom->pred_type = PREDICATE_ATTR;
    }
}


// FIXME: this function should have an optional argument that checks for the uuid.
// this will allow policies to validate their atoms even after an attribute has been aliased.
static bool
__validate_abac_attribute(struct policy_atom * atom)
{
    const struct attribute_term * term             = NULL;
    struct attribute_store      * global_attrstore = abac_acquire_attribute_store(NEXUS_FREAD);

    if (global_attrstore == NULL) {
        log_error("could not acquire attribute_store\n");
        return false;
    }

    term = attribute_store_find_name(global_attrstore, atom->predicate);

    if (term == NULL) {
        log_error("could not find attribute (%s) in store\n", atom->predicate);
        goto out_err;
    }

    if (atom->atom_type == ATOM_TYPE_USER) {
        if (term->type != USER_ATTRIBUTE_TYPE) {
            log_error("the atom_type is `user`, but attribute_type is NOT\n");
            goto out_err;
        }
    } else if (atom->atom_type == ATOM_TYPE_OBJECT) {
        if (term->type != OBJECT_ATTRIBUTE_TYPE) {
            log_error("the atom_type is `object`, but attribute_type is NOT\n");
            goto out_err;
        }
    } else {
        log_error("unknown atom type\n");
        goto out_err;
    }

    nexus_uuid_copy(&term->uuid, &atom->attr_uuid);

    abac_release_attribute_store();

    return true;
out_err:
    abac_release_attribute_store();

    return false;
}

static bool
__validate_system_function(struct policy_atom * atom)
{
    if (atom->atom_type == ATOM_TYPE_OBJECT) {
        if (!system_function_exists(atom->predicate, OBJECT_FUNCTION)) {
            log_error("could not find object function (%s)\n", atom->predicate);
            return false;
        }

        return true;
    } else if (atom->atom_type == ATOM_TYPE_USER) {
        if (!system_function_exists(atom->predicate, USER_FUNCTION)) {
            log_error("could not find user function (%s)\n", atom->predicate);
            return false;
        }

        return true;
    }

    log_error("unknown atom type, can't validate system_function predicate\n");
    return false;
}

bool
policy_atom_is_valid(struct policy_atom * atom)
{
    if (atom->pred_type == PREDICATE_FUNC) {
        return __validate_system_function(atom);
    } else if (atom->pred_type == PREDICATE_ATTR) {
        return __validate_abac_attribute(atom);
    }

    log_error("unknown atom type\n");

    return false;
}

// policy atom ]]--


// --[[ policy rule

static void
__deallocate_policy_atom(void * ptr)
{
    struct policy_atom * atom = ptr;

    policy_atom_free(atom);
}

struct policy_rule *
policy_rule_new(perm_type_t permission)
{
    struct policy_rule * rule = nexus_malloc(sizeof(struct policy_rule));

    rule->perm_type = permission;

    nexus_list_init(&rule->atoms);
    nexus_list_set_deallocator(&rule->atoms, __deallocate_policy_atom);

    nexus_uuid_gen(&rule->rule_uuid);

    return rule;
}

static perm_type_t
__permission_from_string(char * permission_str)
{
    if (strncmp("read", permission_str, 20) == 0) {
        return PERM_READ;
    } else if (strncmp("write", permission_str, 20) == 0) {
        return PERM_WRITE;
    }

    return 0;
}

struct policy_rule *
policy_rule_new_from_perm_str(char * permission_str)
{
    perm_type_t perm = __permission_from_string(permission_str);

    if (perm == 0) {
        log_error("__permission_from_string() FAILED\n");
        return NULL;
    }

    return policy_rule_new(perm);
}

void
policy_rule_free(struct policy_rule * policy_rule)
{
    nexus_list_destroy(&policy_rule->atoms);
    policy_rule->atom_count = 0;
}

char *
policy_rule_datalog_string(struct policy_rule * rule)
{
    char *      result_string = NULL;
    rapidstring string_builder;

    // "10" is arbirtrary, it's my estimate for spacing and commas
    rs_init_w_cap(&string_builder, policy_rule_buf_size(rule) + 10);

    if (__policy_rule_datalog_string(rule, &string_builder)) {
        rs_free(&string_builder);
        log_error("__policy_rule_datalog_string() FAILED\n");
        return NULL;
    }

    result_string = strndup(rs_data_c(&string_builder), rs_len(&string_builder));

    rs_free(&string_builder);

    return result_string;
}

int
__permission_type_to_datalog(perm_type_t perm_type, rapidstring * string_builder)
{
    switch (perm_type) {
    case PERM_READ:
        rs_cat(string_builder, "read(U, O)");
        break;
    case PERM_WRITE:
        rs_cat(string_builder, "write(U, O)");
        break;
    default:
        log_error("invalid policy_rule type\n");
        return -1;
    }

    return 0;
}

int
__policy_rule_datalog_string(struct policy_rule * rule, rapidstring * string_builder)
{
    if (rule->atom_count < 1) {
        log_error("cannot serialize empty rule\n");
        return -1;
    }

    if (__permission_type_to_datalog(rule->perm_type, string_builder)) {
        log_error("__permission_type_to_datalog() FAILED\n");
        return -1;
    }

    rs_cat(string_builder, " :- ");

    {
        struct nexus_list_iterator * iter = list_iterator_new(&rule->atoms);

        int i = 0;

        do {
            struct policy_atom * atom = list_iterator_get(iter);

            if (atom == NULL) {
                break;
            }

            if (i > 0) {
                rs_cat(string_builder, ", ");
            }

            if (__policy_atom_to_str(atom, string_builder)) {
                list_iterator_free(iter);
                log_error("could not convert policy atom to string\n");
                goto out_err;
            }

            i += 1;
            list_iterator_next(iter);
        } while(1);

        list_iterator_free(iter);
    }

    if ((rule->atom_types & ATOM_TYPE_ALL) != ATOM_TYPE_ALL) {
        if ((rule->atom_types & ATOM_TYPE_USER) == 0) {
            rs_cat(string_builder, ", _dummy(U)");
        }

        if ((rule->atom_types & ATOM_TYPE_OBJECT) == 0) {
            rs_cat(string_builder, ", _dummy(O)");
        }
    }

    rs_cat(string_builder, ".");

    return 0;

out_err:
    return -1;
}

int
policy_rule_push_atom(struct policy_rule * rule, struct policy_atom * atom)
{
    nexus_list_append(&rule->atoms, atom);
    rule->atom_count += 1;

    rule->atom_types |= atom->atom_type;

    return 0;
}

size_t
policy_rule_buf_size(struct policy_rule * rule)
{
    size_t total_size = sizeof(struct __policy_rule_hdr);

    struct nexus_list_iterator * iter = list_iterator_new(&rule->atoms);

    while (1) {
        struct policy_atom * atom = list_iterator_get(iter);

        if (atom == NULL) {
            break;
        }

        total_size += policy_atom_buf_size(atom);

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return total_size;
}

uint8_t *
policy_rule_to_buf(struct policy_rule * rule, uint8_t * buffer, size_t buflen)
{
    struct __policy_rule_hdr * header = (struct __policy_rule_hdr *)buffer;

    size_t total_size = policy_rule_buf_size(rule);


    if (buflen < total_size) {
        log_error("serialization buffer is too small. min=%zu, buflen=%zu\n", total_size,
                buflen);
        return NULL;
    }

    // serialize th header
    {
        header->perm_type  = rule->perm_type;
        header->atom_count = rule->atom_count;
        nexus_uuid_copy(&rule->rule_uuid, &header->rule_uuid);
    }

    buffer += sizeof(struct __policy_rule_hdr);
    buflen -= sizeof(struct __policy_rule_hdr);

    // serialize the atoms
    {
        struct nexus_list_iterator * iter = list_iterator_new(&rule->atoms);

        while (1) {
            struct policy_atom * atom = list_iterator_get(iter);

            if (atom == NULL) {
                break;
            }

            buffer = policy_atom_to_buf(atom, buffer, buflen);

            if (buffer == NULL) {
                log_error("policy_atom_to_buf() FAILED\n");
                list_iterator_free(iter);
                return NULL;
            }

            buflen -= policy_atom_buf_size(atom);

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }

    return buffer;
}

struct policy_rule *
policy_rule_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_dest_ptr)
{
    struct policy_rule  * policy_rule = NULL;

    struct __policy_rule_hdr * header = (struct __policy_rule_hdr *)buffer;


    if (buflen < sizeof(struct __policy_rule_hdr)) {
        log_error("serialization buffer is too small. min=%zu, buflen=%zu\n",
                  sizeof(struct __policy_rule_hdr),
                  buflen);
        return NULL;
    }

    policy_rule = nexus_malloc(sizeof(struct policy_rule));

    nexus_list_init(&policy_rule->atoms);
    nexus_list_set_deallocator(&policy_rule->atoms, __deallocate_policy_atom);

    // parse the header
    {
        policy_rule->perm_type  = header->perm_type;
        policy_rule->atom_count = header->atom_count;
        nexus_uuid_copy(&header->rule_uuid, &policy_rule->rule_uuid);
    }

    buffer += sizeof(struct __policy_rule_hdr);
    buflen -= sizeof(struct __policy_rule_hdr);

    policy_rule->atom_count = 0;

    // parse the atoms
    for (size_t i = 0; i < header->atom_count; i++) {
        uint8_t * next_ptr = NULL;

        struct policy_atom * atom = policy_atom_from_buf(buffer, buflen, &next_ptr);

        if (atom == NULL) {
            log_error("policy_atom_from_buf() FAILED\n");
            goto out_err;
        }

        buflen -= (next_ptr - buffer);
        buffer = next_ptr;

        policy_rule_push_atom(policy_rule, atom);
    }

    if (policy_rule->atom_count != header->atom_count) {
        log_error("policy rule atom count is incorrect\n");
        goto out_err;
    }

    *output_dest_ptr = buffer;

    return policy_rule;
out_err:
    policy_rule_free(policy_rule);

    return NULL;
}

// policy rule ]]--
