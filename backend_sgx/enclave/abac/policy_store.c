#include "policy_store.h"

#include <nexus_str.h>


struct __policy_store_hdr {
    struct nexus_uuid   my_uuid;
    struct nexus_uuid   root_uuid;

    __mac_and_version_bytes_t attribute_store_macversion_bytes;

    uint32_t            rules_count;
} __attribute__((packed));


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

    return 0;
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
        log_error("__serialize_rules() FAILED\n");
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

    __policy_store_set_dirty(policy_store);

    return 0;
}

int
policy_store_del(struct policy_store * policy_store, struct nexus_uuid * rule_uuid)
{
    if (__del_policy_rule(policy_store, rule_uuid)) {
        log_error("__del_policy_rule() FAILED\n");
        return -1;
    }

    __policy_store_set_dirty(policy_store);

    return 0;
}


static uint8_t *
__export_policy_rule(struct policy_rule * policy_rule, uint8_t * buffer, size_t buflen)
{
    struct nxs_policy_rule * exported_rule = (struct nxs_policy_rule *)buffer;

    char * policy_string = policy_rule_datalog_string(policy_rule);

    size_t total_len = 0;

    if (policy_string == NULL) {
        log_error("could not export policy string\n");
        return NULL;
    }

    total_len = strnlen(policy_string, NEXUS_POLICY_MAXLEN) + sizeof(struct nxs_policy_rule) + 1;

    if (total_len > buflen) {
        log_error("export buffer is too small. rule_size=%zu, buflen=%zu\n", total_len, buflen);
        goto out_err;
    }

    // perform the export
    nexus_uuid_copy(&policy_rule->rule_uuid, &exported_rule->rule_uuid);
    strncpy(&exported_rule->rule_str, policy_string, NEXUS_POLICY_MAXLEN);
    exported_rule->total_len = total_len;

    nexus_free(policy_string);

    return (buffer + total_len);
out_err:
    nexus_free(policy_string);

    return NULL;
}

int
policy_store_ls(struct policy_store * policy_store,
                uint8_t *             output_bufptr,
                size_t                output_buflen,
                size_t                offset,
                size_t *              total_count,
                size_t *              result_count)
{
    struct nexus_list_iterator * iter = list_iterator_new(&policy_store->rules_list);

    uint8_t * next_outptr = NULL;

    size_t count = 0;

    do {
        if (offset) {
            offset -= 1;
            goto skip;
        }

        struct policy_rule * policy_rule = list_iterator_get(iter);

        if (policy_rule == NULL) {
            break;
        }

        // export the policy_rule
        next_outptr = __export_policy_rule(policy_rule, output_bufptr, output_buflen);
        if (next_outptr == NULL) {
            log_error("__export_policy_rule() FAILED\n");
            goto out_err;
        }

        output_buflen -= (next_outptr - output_bufptr);
        output_bufptr = next_outptr;

        count += 1;
skip:
        list_iterator_next(iter);
    } while(list_iterator_is_valid(iter));


    *result_count = count;
    *total_count  = policy_store->rules_count;

    list_iterator_free(iter);

    return 0;
out_err:
    list_iterator_free(iter);

    return -1;
}


struct nexus_list *
policy_store_select_rules(struct policy_store * policy_store, perm_type_t permission)
{
    struct nexus_list          * filtered_list  = NULL;
    struct nexus_list_iterator * iter_all_rules = NULL;

    size_t count = 0;

    if (policy_store->rules_count == 0) {
        return NULL;
    }


    filtered_list = nexus_malloc(sizeof(struct nexus_list));
    nexus_list_init(filtered_list);

    iter_all_rules = list_iterator_new(&policy_store->rules_list);

    do {
        struct policy_rule * rule = list_iterator_get(iter_all_rules);

        if (rule->perm_type == permission) {
            nexus_list_append(filtered_list, rule);
            count += 1;
        }

        list_iterator_next(iter_all_rules);
    } while(list_iterator_is_valid(iter_all_rules));

    if (count == 0) {
        nexus_free(filtered_list);
        return NULL;
    }

    return filtered_list;
}
