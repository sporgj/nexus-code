#pragma once

#include "nexus.h"
#include "queue.h"

/* used by the VFS to manage traversed paths */
struct path_element {
    struct uuid uuid;
    TAILQ_ENTRY(path_element) next_item;
};

struct path_builder {
    size_t count;  // count[path_elements]
    TAILQ_HEAD(path_list, path_element) path_head;
};

struct path_builder *
path_alloc();

int
path_push(struct path_builder * builder, struct uuid * uuid);

int
path_pop(struct path_builder * builder);

void
path_free(struct path_builder * builder);

char *
path_string(struct path_builder * builder, const char * metadata_dirpath);
