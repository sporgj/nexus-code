#include "nexus_mstore_internal.h"

struct path_builder *
path_alloc()
{
    struct path_builder * builder = NULL;
    builder = (struct path_builder *)calloc(1, sizeof(struct path_builder));
    if (builder == NULL) {
        log_error("allocation error");
        return NULL;
    }

    TAILQ_INIT(&builder->path_head);

    return builder;
}

int
path_push(struct path_builder * builder, struct uuid * uuid)
{
    struct path_element * element = NULL;

    element = (struct path_element *)calloc(1, sizeof(struct path_element));
    if (element == NULL) {
        log_error("allocation error");
        return -1;
    }

    memcpy(&element->uuid, uuid, sizeof(struct uuid));

    builder->count += 1;
    TAILQ_INSERT_TAIL(&builder->path_head, element, next_item);

    return 0;
}

int
path_pop(struct path_builder * builder)
{
    struct path_element * element = NULL;
    // XXX: does this ever return NULL?
    element = TAILQ_LAST(&builder->path_head, path_list);
    TAILQ_REMOVE(&builder->path_head, element, next_item);
    free(element);

    return 0;
}

void
path_free(struct path_builder * builder)
{
    struct path_element * curr   = NULL;
    struct path_element * next   = NULL;

    TAILQ_FOREACH_SAFE(curr, &builder->path_head, next_item, next) {
        free(curr);
    }

    free(builder);
}
