#include "policy_store.h"

#include <nexus_str.h>


struct __policy_store_hdr {
    struct nexus_uuid   my_uuid;
    struct nexus_uuid   root_uuid;

    __mac_and_version_bytes_t attribute_store_macversion_bytes;

    uint32_t            rules_count;
} __attribute__((packed));


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



// --[[ policy_store

static void
__deallocate_policy_rule(void * ptr)
{
    struct policy_rule * rule = ptr;
    policy_rule_free(rule);
}


static void
__policy_store_set_dirty(struct policy_store * policy_store)
{
    if (policy_store->metadata) {
        __metadata_set_dirty(policy_store->metadata);
    }
}

static void
policy_store_init(struct policy_store * policy_store)
{
    nexus_list_init(&policy_store->rules_list);
    nexus_list_set_deallocator(&policy_store->rules_list, __deallocate_policy_rule);
}

struct policy_store *
policy_store_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid)
{
    struct policy_store * policy_store = nexus_malloc(sizeof(struct policy_store));

    nexus_uuid_copy(root_uuid, &policy_store->root_uuid);
    nexus_uuid_copy(uuid, &policy_store->my_uuid);

    policy_store_init(policy_store);

    return policy_store;
}

void
policy_store_free(struct policy_store * policy_store)
{
    nexus_list_destroy(&policy_store->rules_list);
    nexus_free(policy_store);
}


static size_t
__policy_store_buf_size(struct policy_store * policy_store)
{
    struct nexus_list_iterator * iter = list_iterator_new(&policy_store->rules_list);

    size_t rules_size = 0;

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        if (rule == NULL) {
            break;
        }

        rules_size += policy_rule_buf_size(rule);

        list_iterator_next(iter);
    } while (1);

    list_iterator_free(iter);

    return (sizeof(struct __policy_store_hdr) + rules_size);
}

static int
__put_policy_rule(struct policy_store * policy_store, struct policy_rule * policy_rule)
{
    nexus_list_append(&policy_store->rules_list, policy_rule);
    policy_store->rules_count += 1;
}

static int
__del_policy_rule(struct policy_store * policy_store, struct nexus_uuid * uuid)
{
    struct nexus_list_iterator * iter = list_iterator_new(&policy_store->rules_list);

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        if (rule == NULL) {
            break;
        }

        if (nexus_uuid_compare(&rule->rule_uuid, uuid) == 0) {
            policy_store->rules_count -= 1;
            list_iterator_del(iter);
            list_iterator_free(iter);
            return 0;
        }

        list_iterator_next(iter);
    } while (1);

    list_iterator_free(iter);
    return -1;
}

static struct policy_store *
__policy_store_parse(uint8_t * buffer, size_t buflen)
{
    struct policy_store * policy_store = NULL;

    struct __policy_store_hdr * header = (struct __policy_store_hdr *)buffer;

    int bytes_left = buflen;


    if (buflen < sizeof(struct __policy_store_hdr)) {
        log_error("buffer is too small. min=%zu, buflen=%zu\n",
                  sizeof(struct __policy_store_hdr),
                  buflen);
        return NULL;
    }

    // parse the header (rules_count is below)
    policy_store = policy_store_create(&header->root_uuid, &header->my_uuid);

    __mac_and_version_from_buf(&policy_store->attribute_store_macversion,
                               (uint8_t *)&header->attribute_store_macversion_bytes);


    buffer += sizeof(struct __policy_store_hdr);
    bytes_left -= sizeof(struct __policy_store_hdr);

    // add the rules
    for (size_t i = 0; i < header->rules_count; i++) {
        uint8_t        * next_ptr = NULL;
        struct policy_rule * rule = policy_rule_from_buf(buffer, bytes_left, &next_ptr);

        if (rule == NULL) {
            log_error("policy_rule_from_buf() FAILED\n");
            goto out_err;
        }

        // increments the policy_store->rules_count
        if (__put_policy_rule(policy_store, rule)) {
            log_error("__put_policy_rule() FAILED\n");
            goto out_err;
        }

        bytes_left -= (next_ptr - buffer);
        buffer = next_ptr;
    }

    return policy_store;
out_err:
    policy_store_free(policy_store);

    return NULL;
}

struct policy_store *
policy_store_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    return __policy_store_parse(buffer, buflen);
}

static int
__serialize_rules(struct policy_store * policy_store, uint8_t * buffer, size_t buflen)
{
    struct nexus_list_iterator * iter = list_iterator_new(&policy_store->rules_list);

    int bytes_left = buflen;

    do {
        struct policy_rule * rule = list_iterator_get(iter);

        if (rule == NULL) {
            break;
        }

        uint8_t * next_ptr = policy_rule_to_buf(rule, buffer, bytes_left);

        if (next_ptr == NULL) {
            log_error("policy_rule_to_buf() FAILED\n");
            goto out_err;
        }


        bytes_left -= (next_ptr - buffer);
        buffer = next_ptr;

        list_iterator_next(iter);
    } while (1);

    list_iterator_free(iter);

    return 0;
out_err:
    list_iterator_free(iter);

    return -1;
}

static int
__policy_store_serialize(struct policy_store     * policy_store,
                         struct nexus_crypto_buf * crypto_buffer)
{
    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return -1;
    }

    // write the header
    {
         struct __policy_store_hdr * header = (struct __policy_store_hdr *)buffer;

         nexus_uuid_copy(&policy_store->my_uuid, &header->my_uuid);
         nexus_uuid_copy(&policy_store->root_uuid, &header->root_uuid);

         header->rules_count = policy_store->rules_count;

         __mac_and_version_to_buf(&policy_store->attribute_store_macversion,
                                  (uint8_t *)&header->attribute_store_macversion_bytes);
    }

    buffer += sizeof(struct __policy_store_hdr);
    buflen -= sizeof(struct __policy_store_hdr);

    // write the attribute table
    if (__serialize_rules(policy_store, buffer, buflen)) {
        log_error("attribute_table_store() FAILED\n");
        return -1;
    }

    if (nexus_crypto_buf_put(crypto_buffer, &policy_store->mac)) {
        log_error("nexus_crypto_buf_put FAILED\n");
        return -1;
    }

    return 0;
}

int
policy_store_store(struct policy_store * policy_store, uint32_t version, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t serialized_buflen = __policy_store_buf_size(policy_store);


    // update the mac version
    if (abac_global_export_macversion(&policy_store->attribute_store_macversion)) {
        log_error("could not export mac version\n");
        return -1;
    }

    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, version, &policy_store->my_uuid);

    if (crypto_buffer == NULL) {
        log_error("nexus_crypto_buf_new() FAILED\n");
        return -1;
    }

    if (__policy_store_serialize(policy_store, crypto_buffer)) {
        log_error("__policy_store_serialize() FAILED\n");
        goto out_err;
    }

    if (mac) {
        nexus_mac_copy(&policy_store->mac, mac);
    }

    nexus_crypto_buf_free(crypto_buffer);

    return 0;

out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}

int
policy_store_add(struct policy_store * policy_store, struct policy_rule * policy_rule)
{
    if (__put_policy_rule(policy_store, policy_rule)) {
        log_error("__put_policy_rule() FAILED\n");
        return -1;
    }

    return 0;
}

int
policy_store_del(struct policy_store * policy_store, struct nexus_uuid * rule_uuid)
{
    if (__del_policy_rule(policy_store, rule_uuid)) {
        log_error("__del_policy_rule() FAILED\n");
        return -1;
    }

    return 0;
}

// policy_store ]]--



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

void
policy_rule_free(struct policy_rule * policy_rule)
{
    nexus_list_destroy(&policy_rule->atoms);
    policy_rule->atom_count = 0;
}

char *
policy_rule_to_str(struct policy_rule * rule)
{
    if (rule->atom_count < 1) {
        log_error("cannot serialize empty rule\n");
        return NULL;
    }

    // TODO
    return NULL;
}

int
policy_rule_push_atom(struct policy_rule * rule, struct policy_atom * atom)
{
    nexus_list_append(&rule->atoms, atom);
    rule->atom_count += 1;

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

    buffer += total_size;
    buflen -= total_size;

    // serialize the atoms
    {
        struct nexus_list_iterator * iter = list_iterator_new(&rule->atoms);

        size_t atom_bufsize = 0;

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

            atom_bufsize = policy_atom_buf_size(atom);

            buflen -= atom_bufsize;
            total_size += atom_bufsize;

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


    // parse the atoms
    for (size_t i = 0; i < policy_rule->atom_count; i++) {
        uint8_t * next_ptr = NULL;

        struct policy_atom * atom = policy_atom_from_buf(buffer, buflen, &next_ptr);

        if (atom == NULL) {
            log_error("policy_atom_from_buf() FAILED\n");
            goto out_err;
        }

        buflen -= (next_ptr - buffer);
        buffer = next_ptr;

        nexus_list_append(&policy_rule->atoms, atom);
    }

    *output_dest_ptr = buffer;

    return policy_rule;
out_err:
    policy_rule_free(policy_rule);

    return NULL;
}

// policy rule ]]--



// --[[ policy atom

static void
__free_nexus_str(void * el)
{
    struct nexus_string * nexus_str = (struct nexus_string *)el;

    nexus_free(nexus_str);
}

struct policy_atom *
policy_atom_new(atom_type_t atom_type, pred_type_t pred_type)
{
    struct policy_atom * atom = nexus_malloc(sizeof(struct policy_atom));

    atom->atom_type = atom_type;
    atom->pred_type = pred_type;

    nexus_list_init(&atom->args_list);
    nexus_list_set_deallocator(&atom->args_list, __free_nexus_str);

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

struct policy_atom *
policy_atom_from_str(char * atr)
{
    // TODO
    return NULL;
}

char *
policy_atom_to_str(struct policy_atom * atom)
{
    // TODO
    return NULL;
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

    atom_buffer->atom_type    = atom->atom_type;
    atom_buffer->pred_type    = atom->pred_type;

    atom_buffer->arity        = atom->arity;
    atom_buffer->args_bufsize = atom->args_bufsize;

    nexus_uuid_copy(&atom->attr_uuid, &atom_buffer->attr_uuid);
    memcpy(atom_buffer->predicate, atom->predicate, SYSTEM_FUNC_MAX_LENGTH);


    // initialize the output_ptr and output_len
    output_ptr = (buffer + atom_buf_size);
    output_len = (buflen - atom_buf_size);

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

            output_len = (uintptr_t)(next_ptr - output_ptr);
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

    struct policy_atom * new_policy_atom = NULL;

    size_t tmp_atom_buf_total_size = sizeof(struct __policy_atom_buf) + tmp_atom_buf->args_bufsize;

    if (buflen < tmp_atom_buf_total_size) {
        log_error("the atom buffer is too small. buflen=%zu, atom_bufsize=%zu\n",
                  buflen,
                  tmp_atom_buf_total_size);
        return NULL;
    }

    // initializes the args_list
    new_policy_atom = policy_atom_new(tmp_atom_buf->atom_type, tmp_atom_buf->pred_type);

    nexus_uuid_copy(&tmp_atom_buf->attr_uuid, &new_policy_atom->attr_uuid);
    memcpy(new_policy_atom->predicate, tmp_atom_buf->predicate, SYSTEM_FUNC_MAX_LENGTH);

    new_policy_atom->arity        = tmp_atom_buf->arity;
    new_policy_atom->args_bufsize = tmp_atom_buf->args_bufsize;

    // parse the args buffer
    {
        uint8_t             * buffer    = tmp_atom_buf->args_buffer;
        struct nexus_string * nexus_str = NULL;

        for (size_t i = 0; i < tmp_atom_buf->arity; i++) {
            nexus_str = nexus_string_from_buf(buffer, buflen, output_ptr);
            nexus_list_append(&new_policy_atom->args_list, nexus_str);
            buffer = *output_ptr;
        }
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
}

// policy atom ]]--
