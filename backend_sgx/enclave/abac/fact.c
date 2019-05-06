#include "abac_internal.h"
#include "fact.h"
#include "db.h"

#include <libnexus_trusted/offsetof.h>


static struct kb_fact *
__new_cached_fact(struct nexus_uuid * uuid, char * name, const char * value)
{
    struct kb_fact * new_fact = nexus_malloc(sizeof(struct kb_fact));

    if (uuid) {
        nexus_uuid_copy(uuid, &new_fact->uuid);
    }

    strncpy(new_fact->name, name, ATTRIBUTE_NAME_MAX);

    kb_fact_update_value(new_fact, value);

    INIT_LIST_HEAD(&new_fact->db_list);
    INIT_LIST_HEAD(&new_fact->entity_lru);

    return new_fact;
}

void
kb_fact_update_value(struct kb_fact * fact, const char * value)
{
    if (fact->value) {
        nexus_free(fact->value);
        fact->value = NULL;
    }

    if (value) {
        fact->value = strndup(value, ATTRIBUTE_VALUE_SIZE);
    }
}

void
kb_fact_free(struct kb_fact * cached_fact)
{
    list_del(&cached_fact->entity_lru);
    list_del(&cached_fact->db_list);

    if (cached_fact->value) {
        nexus_free(cached_fact->value);
    }

    nexus_free(cached_fact);
}


struct kb_fact *
__kb_fact_from_db_list(struct list_head * db_list_ptr)
{
    return container_of(db_list_ptr, struct kb_fact, db_list);
}

struct kb_fact *
__kb_fact_from_entity_list(struct list_head * entity_list_ptr)
{
    return container_of(entity_list_ptr, struct kb_fact, entity_lru);
}

static int
__uuid_facts_cmp(const void           * data,
                 const struct kb_fact * entry1,
                 const struct kb_fact * entry2,
                 const void           * keydata)
{
    return nexus_uuid_compare(&entry1->uuid, &entry2->uuid);
}

static int
__name_facts_cmp(const void           * data,
                 const struct kb_fact * entry1,
                 const struct kb_fact * entry2,
                 const void           * keydata)
{
    return strncmp(entry1->name, entry2->name, ATTRIBUTE_NAME_MAX);
}


struct kb_entity *
kb_entity_new(struct nexus_uuid * uuid, attribute_type_t attribute_type)
{
    struct kb_entity * entity = nexus_malloc(sizeof(struct kb_entity));

    nexus_uuid_copy(uuid, &entity->uuid);
    entity->uuid_str = nexus_uuid_to_hex(uuid);

    entity->attr_type = attribute_type;

    hashmap_init(&entity->uuid_facts, (hashmap_cmp_fn)__uuid_facts_cmp, NULL, 17);
    hashmap_init(&entity->name_facts, (hashmap_cmp_fn)__name_facts_cmp, NULL, 7);

    nexus_list_init(&entity->uuid_facts_lru);

    return entity;
}

static void
__delete_element_facts(struct kb_entity * entity, struct hashmap * facts_map)
{
    struct hashmap_iter iter;

    hashmap_iter_init(facts_map, &iter);

    do {
        struct kb_fact * cached_fact = hashmap_iter_next(&iter);

        if (cached_fact == NULL) {
            break;
        }

        if (cached_fact->is_inserted && !cached_fact->is_rule) {
            if (db_retract_fact(cached_fact)) {
                log_error("retract_db_fact() FAILED\n");
            }
        }

        list_del_init(&cached_fact->entity_lru);
        kb_fact_free(cached_fact);
    } while (1);

    hashmap_free(facts_map, 0);
}

void
kb_entity_free(struct kb_entity * entity)
{
    __delete_element_facts(entity, &entity->uuid_facts);
    __delete_element_facts(entity, &entity->name_facts);

    nexus_free(entity->uuid_str);
    nexus_free(entity);
}

struct kb_fact *
kb_entity_put_uuid_fact(struct kb_entity  * entity,
                        struct nexus_uuid * uuid,
                        char              * name,
                        const char        * value)
{
    struct kb_fact * new_fact = __new_cached_fact(uuid, name, value);

    hashmap_entry_init(new_fact, memhash(&new_fact->uuid, sizeof(struct nexus_uuid)));

    hashmap_add(&entity->uuid_facts, &new_fact->hash_entry);

    list_add_tail(&new_fact->entity_lru, &entity->uuid_facts_lru);

    entity->uuid_facts_count += 1;

    new_fact->entity = entity;
    new_fact->is_uuid_fact = true;

    return new_fact;
}

struct kb_fact *
kb_entity_put_name_fact(struct kb_entity * entity, char * name, const char * value)
{
    struct kb_fact * new_fact = __new_cached_fact(NULL, name, value);

    hashmap_entry_init(new_fact, strhash(new_fact->name));

    hashmap_add(&entity->name_facts, &new_fact->hash_entry);

    new_fact->entity = entity;

    entity->name_facts_count += 1;

    return new_fact;
}


struct kb_fact *
kb_entity_find_uuid_fact(struct kb_entity * entity, struct nexus_uuid * uuid)
{
    struct kb_fact   tmp_fact = {0};

    nexus_uuid_copy(uuid, &tmp_fact.uuid);
    hashmap_entry_init(&tmp_fact, memhash(&tmp_fact.uuid, sizeof(struct nexus_uuid)));

    return hashmap_get(&entity->uuid_facts, &tmp_fact, NULL);
}

int
kb_entity_del_uuid_fact(struct kb_entity * entity, struct kb_fact * fact)
{
    if ((entity != fact->entity) || !(fact->is_uuid_fact)) {
        log_error("cached fact does not belong to entity\n");
        return -1;
    }

    __hashmap_remove_entry(&entity->uuid_facts, &fact->hash_entry);

    fact->entity = NULL;

    entity->uuid_facts_count -= 1;

    kb_fact_free(fact);

    return 0;
}

struct kb_fact *
kb_entity_find_name_fact(struct kb_entity * entity, char * name)
{
    struct kb_fact   tmp_fact = {0};

    strncpy(tmp_fact.name, name, ATTRIBUTE_NAME_MAX);
    hashmap_entry_init(&tmp_fact, strhash(tmp_fact.name));

    return hashmap_get(&entity->name_facts, &tmp_fact, NULL);
}

int
kb_entity_del_name_fact(struct kb_entity * entity, struct kb_fact * fact)
{
    if ((entity != fact->entity) || (fact->is_uuid_fact)) {
        log_error("cached fact does not belong to entity or is uuid fact\n");
        return -1;
    }

    __hashmap_remove_entry(&entity->uuid_facts, &fact->hash_entry);

    fact->entity = NULL;

    entity->name_facts_count -= 1;

    kb_fact_free(fact);

    return 0;
}

bool
kb_entity_needs_refresh(struct kb_entity * entity, struct nexus_metadata * metadata)
{
    if (entity->metadata_version != metadata->version) {
        return true;
    }

    if (!entity->is_fully_asserted) {
        return true;
    }

    return false;
}

void
kb_entity_assert_fully(struct kb_entity * entity, struct nexus_metadata * metadata)
{
    entity->is_fully_asserted = true;
    entity->metadata_version  = metadata->version;
}


void
kb_fact_warm_up(struct kb_fact * fact)
{
    if (!fact->is_uuid_fact || !fact->entity) {
        return;
    }

    list_move(&fact->entity_lru, &fact->entity->uuid_facts_lru);
}

void
kb_fact_cool_down(struct kb_fact * fact)
{
    if (!fact->is_uuid_fact || !fact->entity) {
        return;
    }

    list_del_init(&fact->entity_lru);
    list_add_tail(&fact->entity_lru, &fact->entity->uuid_facts_lru);
}
