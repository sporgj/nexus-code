#include "abac_internal.h"
#include "policy_rule.h"
#include "atom.h"

#include "../libnexus_trusted/nexus_str.h"
#include "../libnexus_trusted/rapidstring.h"


struct __policy_rule_hdr {
    perm_type_t             perm_type;

    uint16_t                atom_count;

    struct nexus_uuid       rule_uuid;
} __attribute__((packed));


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
    nexus_free(policy_rule);
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

            if (__policy_atom_to_str(atom, true, string_builder)) {
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
