#pragma once


/**
 * stores the list of hardlinked filenodes
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */


struct hardlink_table {
    struct nexus_uuid            my_uuid;
    struct nexus_uuid            root_uuid;

    size_t                       count;

    struct nexus_mac             mac;

    struct nexus_hashtable     * hashtable;

    struct nexus_metadata      * metadata;
};


struct hardlink_table *
hardlink_table_create(struct nexus_uuid * table_uuid, struct nexus_uuid * root_uuid);

bool
hardlink_table_contains_uuid(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid);

/**
 * Increments the number of links on the uuid
 */
int
hardlink_table_incr_uuid(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid);


/**
 * Decrements the number of links on the uuid
 */
int
hardlink_table_decr_uuid(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid);


struct hardlink_table *
hardlink_table_load(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_mac * mac);

int
hardlink_table_reload(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid, nexus_io_flags_t flags);


// make sure you've called hardlink_table_lock()

int
hardlink_table_store(struct hardlink_table * hardlink_table, size_t version, struct nexus_mac * mac);

int
hardlink_table_lock(struct hardlink_table * hardlink_table, nexus_io_flags_t flags);

void
hardlink_table_unlock(struct hardlink_table * hardlink_table);

struct hardlink_table *
hardlink_table_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer, nexus_io_flags_t flags);
