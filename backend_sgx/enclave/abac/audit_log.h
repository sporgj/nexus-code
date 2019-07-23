#pragma once

#include "abac_internal.h"

struct audit_log {
    struct nexus_uuid        uuid;

    size_t                   event_count;

    size_t                   max_log_count;

    size_t                   last_audit_size;

    struct list_head         events_list;


    struct nexus_mac         mac;

    struct nexus_metadata  * metadata;
};


struct audit_log *
audit_log_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid);

void
audit_log_free(struct audit_log * audit_log);

struct audit_log *
audit_log_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer);

int
audit_log_store(struct audit_log * audit_log, size_t version, struct nexus_mac * mac);

int
audit_log_add_event(struct audit_log  * audit_log,
                    perm_type_t         perm,
                    struct nexus_uuid * uuid,
                    size_t              version);

int
audit_log_add_event(struct audit_log  * audit_log,
                    perm_type_t         perm,
                    struct nexus_uuid * uuid,
                    size_t              version);
