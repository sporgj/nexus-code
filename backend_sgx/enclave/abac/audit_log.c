#include "audit_log.h"

#define MAX_EVENT_COUNT  100


struct __audit_log_hdr {
    struct nexus_uuid my_uuid;

    uint32_t    event_count;
    uint32_t    max_log_count;
};


struct __audit_log_event {
    uint64_t version;
    perm_type_t  perm;
    struct nexus_uuid  uuid;
} __attribute__((packed));


struct audit_event {
    struct __audit_log_event _evt;

    struct list_head node;
};


static void
__audit_log_set_dirty(struct audit_log * audit_log)
{
    if (audit_log->metadata) {
        __metadata_set_dirty(audit_log->metadata);
    }
}

static size_t
__audit_log_buf_size(struct audit_log * audit_log)
{
    return sizeof(struct __audit_log_hdr)
           + (sizeof(struct __audit_log_event) * audit_log->event_count);
}


struct audit_log *
audit_log_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid)
{
    struct audit_log * audit_log = nexus_malloc(sizeof(struct audit_log));

    nexus_uuid_copy(uuid, &audit_log->uuid);

    INIT_LIST_HEAD(&audit_log->events_list);

    audit_log->max_log_count = MAX_EVENT_COUNT;

    return audit_log;
}


void
audit_log_free(struct audit_log * audit_log)
{
    struct list_head * curr = NULL;
    struct list_head * next = NULL;

    list_for_each_safe(curr, next, &audit_log->events_list) {
        struct audit_event * event = container_of(curr, struct audit_event, node);

        nexus_free(event);
    }

    nexus_free(audit_log);
}

static int
__audit_log_put(struct audit_log * audit_log, struct __audit_log_event * _evt)
{
    if (audit_log->event_count == audit_log->max_log_count) {
        // pop the first element
        struct audit_event * last_event = NULL;

        last_event = list_first_entry(&audit_log->events_list, struct audit_event, node);

        list_del(&last_event->node);
        nexus_free(last_event);

        audit_log->event_count -= 1;
    }

    struct audit_event * audit_event = nexus_malloc(sizeof(struct audit_event));
    INIT_LIST_HEAD(&audit_event->node);
    memcpy(&audit_event->_evt, _evt, sizeof(struct __audit_log_event));

    list_add_tail(&audit_event->node, &audit_log->events_list);

    audit_log->event_count += 1;

    return 0;
}

static struct audit_log *
__audit_log_parse(uint8_t * buffer, size_t buflen)
{
    struct audit_log       * audit_log = NULL;

    struct __audit_log_hdr * header    = (struct __audit_log_hdr *)buffer;

    int bytes_left = buflen;

    if (buflen < sizeof(struct __audit_log_hdr)) {
        log_error("buffer is too small to fit header\n");
        return NULL;;
    }


    audit_log = audit_log_create(NULL, &header->my_uuid);

    audit_log->max_log_count = header->max_log_count;

    buffer += sizeof(struct __audit_log_hdr);
    buflen -= sizeof(struct __audit_log_hdr);

    // adjusts event_count
    for (size_t i = 0; i < header->event_count; i++) {
        if (buflen < sizeof(struct __audit_log_event)) {
            log_error("buffer too small to parse event\n");
            goto out_err;
        }

        struct __audit_log_event * _evt = (struct __audit_log_event *)buffer;

        if (__audit_log_put(audit_log, _evt)) {
            log_error("audit_log_add_event() FAILED\n");
            goto out_err;
        }

        buffer += sizeof(struct __audit_log_event);
        buflen -= sizeof(struct __audit_log_event);
    }

    if (audit_log->event_count != header->event_count) {
        log_error("event count does not match: actual=%zu, expected=%zu\n",
                  audit_log->event_count,
                  header->event_count);
        goto out_err;
    }

    return audit_log;
out_err:
    audit_log_free(audit_log);

    return NULL;
}

struct audit_log *
audit_log_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    return __audit_log_parse(buffer, buflen);
}

static int
__audit_log_serialize(struct audit_log * audit_log, struct nexus_crypto_buf * crypto_buffer)
{
    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    struct list_head * curr = NULL;

    {
        struct __audit_log_hdr * header = (struct __audit_log_hdr *)buffer;

        header->event_count   = audit_log->event_count;
        header->max_log_count = audit_log->max_log_count;

        nexus_uuid_copy(&audit_log->uuid, &header->my_uuid);
    }

    buffer += sizeof(struct __audit_log_hdr);
    buflen -= sizeof(struct __audit_log_hdr);

    list_for_each(curr, &audit_log->events_list) {
        if (buflen < sizeof(struct __audit_log_event)) {
            log_error("no space for serializing audit log event\n");
            return -1;
        }

        struct __audit_log_event * _dest_evt = (struct __audit_log_event *)buffer;

        struct audit_event * event = container_of(curr, struct audit_event, node);

        memcpy(_dest_evt, &event->_evt, sizeof(struct __audit_log_event));

        buffer += sizeof(struct __audit_log_event);
        buflen -= sizeof(struct __audit_log_event);
    }

    if (nexus_crypto_buf_put(crypto_buffer, &audit_log->mac)) {
        log_error("nexus_crypto_buf_put FAILED\n");
        return -1;
    }

    return 0;
}

int
audit_log_store(struct audit_log * audit_log, size_t version, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t serialized_buflen = __audit_log_buf_size(audit_log);

    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, version, &audit_log->uuid);

    if (crypto_buffer == NULL) {
        log_error("nexus_crypto_buf_new() FAILED\n");
        return -1;
    }

    if (__audit_log_serialize(audit_log, crypto_buffer)) {
        log_error("__audit_log_serialize() FAILED\n");
        goto out_err;
    }

    if (mac) {
        nexus_mac_copy(&audit_log->mac, mac);
    }

    nexus_crypto_buf_free(crypto_buffer);

    return 0;
out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}

int
audit_log_add_event(struct audit_log  * audit_log,
                    perm_type_t         perm,
                    struct nexus_uuid * uuid,
                    size_t              version)
{
    struct audit_event * audit_event = nexus_malloc(sizeof(struct audit_event));

    struct __audit_log_event _evt = { 0 };

    _evt.perm = perm;
    _evt.version = version;
    nexus_uuid_copy(uuid, &_evt.uuid);

    if (__audit_log_put(audit_log, &_evt)) {
        log_error("__audit_log_put() FAILED\n");
        return -1;
    }

    __audit_log_set_dirty(audit_log);

    return 0;
}

int
audit_log_complete_write(struct audit_log * audit_log, size_t new_version)
{
    // get the last element and check if there's need for version change
    struct audit_event * event = NULL;

    event = list_last_entry(&audit_log->events_list, struct audit_event, node);

    if (!perm_type_modifies_object(event->_evt.perm)) {
        char * perm_string = perm_type_to_string(event->_evt.perm);
        log_error("Permission type ('%s') is not a write-permission\n", perm_string);
        nexus_free(perm_string);
        return -1;
    }

    if (event->_evt.version >= new_version) {
        log_error("new version has to be greater. old_version=%zu, new_version=%zu\n",
                  event->_evt.version,
                  new_version);
        return -1;
    }

    event->_evt.version = new_version;

    __audit_log_set_dirty(audit_log);

    return 0;
}


int
audit_log_print(struct audit_log * audit_log, struct nexus_usertable * usertable)
{
    struct list_head * curr = NULL;

    size_t count = 0;

    nexus_printf("EVENT COUNT = %zu\n", audit_log->event_count);

    list_for_each(curr, &audit_log->events_list) {
        struct audit_event * event = container_of(curr, struct audit_event, node);

        struct nexus_user * user = nexus_usertable_find_uuid(usertable, &event->_evt.uuid);

        if (user == NULL) {
            log_error("could not find user entry\n");
            continue;
        }

        char * permission_string = perm_type_to_string(event->_evt.perm);

        nexus_printf("[%s] %s\n", user->name, permission_string);

        nexus_free(permission_string);

        count++;
        if (count == 10) {
            break;
        }
    }

    return 0;
}
