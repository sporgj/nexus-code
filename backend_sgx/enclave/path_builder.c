struct path_builder {
    size_t count;
    struct nexus_list uuids;
};


void
path_builder_init(struct path_builder * builder)
{
    memset(builder, 0, sizeof(struct path_builder));

    nexus_list_init(&builder->uuids);
}

void
path_builder_push(struct path_builder * builder, struct nexus_uuid * uuid)
{
    nexus_list_append(&builder->uuids, uuid);
    builder->count += 1;
}

int
path_builder_pop(struct path_builder * builder)
{
    if (builder->count == 0) {
        return -1;
    }

    nexus_list_pop(&builder->uuids);
    builder->count -= 1;

    return 0;
}

void
path_builder_free(struct path_builder * builder)
{
    nexus_list_destroy(&builder->uuids);
}

struct nexus_uuid_path *
path_builder_get_path(struct path_builder * builder)
{
    struct nexus_uuid_path * uuid_path = NULL;

    if (builder->count == 0) {
        return NULL;
    }

    uuid_path = nexus_malloc(sizeof(struct nexus_uuid_path) + sizeof(struct nexus_uuid) * builder->count);

    {
        struct nexus_list_iterator * iter = NULL;

        size_t i = 0;

        iter = list_iterator_new(&builder->uuids);

        while (list_iterator_is_valid(iter)) {
            struct nexus_uuid * curr_uuid = list_iterator_get(iter);

            nexus_uuid_copy(curr_uuid, &uuid_path->uuids[i]);

            i += 1;

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }


    return uuid_path;
}
