#pragma once

/**
 * defines all the functions used by the untrusted code
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <nexus.h>
#include <nexus_metadata_store.h>

#include "nexus_log.h"
#include "nexus_path.h"
#include "nexus_types.h"
#include "nexus_util.h"

#include "queue.h"

// represents cached dirnode/filebox
typedef enum { NEXUS_DIRNODE, NEXUS_FILEBOX } nx_metadata_type_t;

// internally used by the VFS as an in-memory directory cache structure
struct nexus_dentry {
    char *      name;
    size_t      name_len;
    struct uuid uuid;

    struct nexus_dentry *   parent;
    struct nexus_volume *   volume;
    struct nexus_metadata * metadata;

    TAILQ_ENTRY(nexus_dentry) next_item;
    TAILQ_HEAD(dentry_head, nexus_dentry) children;
};

struct volume_entry {
    struct nexus_volume * volume;

    size_t metadata_dirpath_len;
    size_t datafolder_dirpath_len;

    TAILQ_ENTRY(volume_entry) next_item;
};

// operations on metadata files
struct metadata_operations {
    struct nexus_metadata * (*read)(struct nexus_dentry * dentry,
                                    struct path_builder * path);

    int (*write)(struct nexus_metadata * metadata, size_t size);
};

// nexus_volume.c
struct nexus_volume *
alloc_volume(const char * metadata_dirpath, const char * datafolder_dirpath);

void
free_volume(struct nexus_volume * volume);

// nexus_vfs.c

// reads the inode from disk
struct nexus_metadata *
vfs_read_metadata(struct nexus_dentry * dentry, struct path_builder * builder);

// checks for the metadata cache state on disk
int
vfs_revalidate(struct nexus_dentry * dentry);

