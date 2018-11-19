#pragma once

#include <nexus_uuid.h>


struct nexus_metadata;


struct nexus_dentry {
    nexus_metadata_type_t       metadata_type;

    char                      * name;
    size_t                      name_len;

    struct nexus_uuid           link_uuid;

    struct nexus_dentry       * parent;
    struct nexus_metadata     * metadata;

    struct list_head            children;
    struct list_head            siblings;
};

int
revalidate_dentry(struct nexus_dentry * dentry, nexus_io_flags_t flags);

/**
 * Performs a dentry lookups
 * @param root_dentry
 * @param path
 */
struct nexus_dentry *
dentry_lookup(struct nexus_dentry * root_dentry, char * path);

struct nexus_metadata *
dentry_get_metadata(struct nexus_dentry * metadata, nexus_io_flags_t flags, bool revalidate);

void
dentry_delete(struct nexus_dentry * dentry);

/**
 * @param parent_dentry
 * @param child
 */
void
dentry_delete_child(struct nexus_dentry * parent_dentry, const char * child);



