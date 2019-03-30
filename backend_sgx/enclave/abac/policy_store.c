#include "policy_store.h"

#include <nexus_str.h>


struct __policy_store_hdr {
    struct nexus_uuid   my_uuid;
    struct nexus_uuid   root_uuid;

    uint32_t            rules_count;
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


static void
policy_store_init(struct policy_store * policy_store)
{
    // TODO
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
policy_store_destroy(struct policy_store * policy_store)
{
    nexus_list_destroy(&policy_store->rules_list);
    nexus_free(policy_store);
}


struct policy_store *
policy_store_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    // TODO
    return NULL;
}

int
policy_store_store(struct policy_store * policy_store, struct nexus_mac * mac)
{
    // TODO
    return -1;
}

struct policy_rule *
policy_store_add(struct policy_store * policy_store, char * policy_string)
{
    // TODO
    return NULL;
}

int
policy_store_del(struct nexus_uuid * rule_uuid)
{
    return -1;
}



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

uint8_t *
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
