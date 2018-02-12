#include "enclave_internal.h"

#define NEXUS_ACL_VERSION 0x0001

/**
 * this will be serialized unto a buffer
 */
struct __acl_header {
    uint16_t version;

    uint32_t count;
} __attribute__((packed));

static void
init_nexus_acl_list(struct nexus_acl * nexus_acl);

static void
__free_acl_entry(void * element)
{
    nexus_free(element);
}

static uint8_t *
__parse_acl_entry(struct nexus_acl_entry ** acl_entry, uint8_t * in_buffer)
{
    struct nexus_acl_entry * new_acl_entry = NULL;

    size_t size = sizeof(struct nexus_acl_entry);

    new_acl_entry = nexus_malloc(size);

    memcpy(new_acl_entry, (struct nexus_acl_entry *)in_buffer, size);

    return (in_buffer + size);
}

static uint8_t *
__serialize_acl_entry(struct nexus_acl_entry * acl_entry, uint8_t * out_buffer)
{
    memcpy(out_buffer, acl_entry, sizeof(struct nexus_acl_entry));

    return (out_buffer + sizeof(struct nexus_acl_entry));
}

static uint8_t *
__parse_acl_header(struct nexus_acl * nexus_acl, uint8_t * buffer, size_t buflen)
{
    struct __acl_header * header = NULL;

    if (buflen < sizeof(struct __acl_header)) {
        log_error("the acl buffer is too small\n");
        return NULL;
    }

    header = (struct __acl_header *)buffer;

    nexus_acl->count = header->count;

    return buffer + sizeof(struct __acl_header);
}

static uint8_t *
__serialize_acl_header(struct nexus_acl * nexus_acl, uint8_t * buffer)
{
    struct __acl_header * header = (struct __acl_header *) buffer;

    memset(header, 0, sizeof(struct __acl_header));

    header->version = NEXUS_ACL_VERSION;
    header->count   = nexus_acl->count;

    return buffer + sizeof(struct __acl_header);
}

int
__nexus_acl_from_buffer(struct nexus_acl * nexus_acl, uint8_t * buffer, size_t buflen)
{
    uint8_t * input_ptr = NULL;


    nexus_acl_init(nexus_acl);

    input_ptr = __parse_acl_header(nexus_acl, buffer, buflen);

    if (input_ptr == NULL) {
        log_error("could not parse ACL header\n");
        return -1;
    }

    for (size_t i = 0; i < nexus_acl->count; i++) {
        struct nexus_acl_entry * acl_entry = NULL;

        input_ptr = __parse_acl_entry(&acl_entry, input_ptr);

        nexus_list_append(&nexus_acl->acls, acl_entry);
    }

    return 0;
}

int
nexus_acl_to_buffer(struct nexus_acl * nexus_acl, uint8_t * buffer)
{
    uint8_t * output_ptr = NULL;


    output_ptr = __serialize_acl_header(nexus_acl, buffer);

    if (output_ptr == NULL) {
        log_error("could not parse ACL header\n");
        return -1;
    }

    {
        struct nexus_list_iterator * iter = NULL;

        iter = list_iterator_new(&nexus_acl->acls);

        while (list_iterator_is_valid(iter)) {
            struct nexus_acl_entry * acl_entry = list_iterator_get(iter);

            output_ptr = __serialize_acl_entry(acl_entry, output_ptr);

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }

    return 0;
}

static void
init_nexus_acl_list(struct nexus_acl * nexus_acl)
{
    struct nexus_list * acl_list = &nexus_acl->acls;

    nexus_list_init(acl_list);
    nexus_list_set_deallocator(acl_list, __free_acl_entry);
}

void
nexus_acl_init(struct nexus_acl * nexus_acl)
{
    memset(nexus_acl, 0, sizeof(struct nexus_acl));

    init_nexus_acl_list(nexus_acl);
}

void
nexus_acl_free(struct nexus_acl * nexus_acl)
{
    nexus_list_destroy(&nexus_acl->acls);
}

size_t
nexus_acl_size(struct nexus_acl * nexus_acl)
{
    return sizeof(struct __acl_header) + (nexus_acl->count * sizeof(struct nexus_acl_entry));
}

bool
is_action_allowed(struct nexus_acl * nexus_acl, nexus_uid_t uid)
{
    // TODO
    return true;
}

static struct nexus_acl_entry *
add_acl_entry(struct nexus_acl * nexus_acl, nexus_uid_t uid)
{
    struct nexus_acl_entry * acl_entry = NULL;

    acl_entry = nexus_malloc(sizeof(struct nexus_acl_entry));

    acl_entry->uid = uid;

    nexus_list_append(&nexus_acl->acls, acl_entry);

    nexus_acl->count += 1;

    return acl_entry;
}

static struct nexus_list_iterator *
find_acl_entry(struct nexus_acl * nexus_acl, nexus_uid_t uid)
{
    struct nexus_list_iterator * iter = NULL;

    iter = list_iterator_new(&nexus_acl->acls);

    while (list_iterator_is_valid(iter)) {
        struct nexus_acl_entry * acl_entry = list_iterator_get(iter);

        if (acl_entry->uid == uid) {
            return iter;
        }
    }

    list_iterator_free(iter);

    return NULL;
}

bool
is_acl_operation_allowed(struct nexus_acl * nexus_acl)
{
    // TODO check against the currently authenticated user
    return true;
}

int
nexus_acl_set(struct nexus_acl * nexus_acl, nexus_uid_t uid, nexus_perm_t perm)
{
    struct nexus_list_iterator * acl_iter  = NULL;

    struct nexus_acl_entry     * acl_entry = NULL;

    if (!is_acl_operation_allowed(nexus_acl)) {
        return -1;
    }

    acl_iter = find_acl_entry(nexus_acl, uid);

    if (acl_iter == NULL) {
        acl_entry = add_acl_entry(nexus_acl, uid);
    } else {
        acl_entry = list_iterator_get(acl_iter);
        list_iterator_free(acl_iter);
    }

    acl_entry->perm |= perm;

    return 0;
}

int
nexus_acl_unset(struct nexus_acl * nexus_acl, nexus_uid_t uid, nexus_perm_t perm)
{
    struct nexus_list_iterator * acl_iter  = NULL;

    struct nexus_acl_entry     * acl_entry = NULL;

    if (!is_acl_operation_allowed(nexus_acl)) {
        return -1;
    }

    acl_iter = find_acl_entry(nexus_acl, uid);

    // if there is no user, the unset is a no-op
    if (acl_iter == NULL) {
        return 0;
    }

    acl_entry = list_iterator_get(acl_iter);

    list_iterator_free(acl_iter);

    acl_entry->perm |= (~perm);

    return 0;
}

int
nexus_acl_remove(struct nexus_acl * nexus_acl, nexus_uid_t uid)
{
    struct nexus_list_iterator * acl_iter  = NULL;

    if (!is_acl_operation_allowed(nexus_acl)) {
        return -1;
    }

    acl_iter = find_acl_entry(nexus_acl, uid);

    if (acl_iter == NULL) {
        return 0;
    }

    list_iterator_del(acl_iter);

    nexus_acl->count -= 1;

    list_iterator_free(acl_iter);

    return 0;
}

bool
nexus_acl_check(struct nexus_acl * nexus_acl, nexus_perm_t perm)
{
    // TODO
    return true;
}
