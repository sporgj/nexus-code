struct path_builder {
    size_t count;
    struct nexus_list uuids;
};


static void
path_builder_init(struct path_builder * builder)
{
    memset(builder, 0, sizeof(struct path_builder));

    nexus_list_init(&builder->uuids);
}

static void
path_builder_push(struct path_builder * builder, struct nexus_uuid * uuid)
{
    nexus_list_append(&builder->uuids, uuid);
    builder->count += 1;
}

static int
path_builder_pop(struct path_builder * builder)
{
    if (builder->count == 0) {
        return -1;
    }

    nexus_list_pop(&builder->uuids);
    builder->count -= 1;

    return 0;
}

static void
path_builder_free(struct path_builder * builder)
{
    nexus_list_destroy(&builder->uuids);
}
