#include "abac_internal.h"
#include "fact.h"
#include "db.h"


static struct __cached_fact *
__new_cached_fact(struct nexus_uuid * uuid, char * name, char * value)
{
    struct __cached_fact * new_fact = nexus_malloc(sizeof(struct __cached_fact));

    if (uuid) {
        nexus_uuid_copy(uuid, &new_fact->uuid);
    }

    strncpy(&new_fact->name, name, ATTRIBUTE_NAME_MAX);
    new_fact->value = value;

    return new_fact;
}

static void
__free_cached_fact(struct __cached_fact * cached_fact)
{
    if (cached_fact->value) {
        nexus_free(cached_fact->value);
    }

    nexus_free(cached_fact);
}

static int
__uuid_facts_cmp(const void                 * data,
                 const struct __cached_fact * entry1,
                 const struct __cached_fact * entry2,
                 const void                 * keydata)
{
    return nexus_uuid_compare(&entry1->uuid, &entry2->uuid);
}

static int
__name_facts_cmp(const void                 * data,
                 const struct __cached_fact * entry1,
                 const struct __cached_fact * entry2,
                 const void                 * keydata)
{
    return strncmp(entry1->name, entry2->name, ATTRIBUTE_NAME_MAX);
}


struct __cached_element *
cached_element_new(struct nexus_uuid * uuid)
{
    struct __cached_element * cached_element = nexus_malloc(sizeof(struct __cached_element));

    nexus_uuid_copy(uuid, &cached_element->uuid);
    cached_element->uuid_str = nexus_uuid_to_hex(uuid);

    hashmap_init(&cached_element->uuid_facts, (hashmap_cmp_fn)__uuid_facts_cmp, NULL, 17);
    hashmap_init(&cached_element->name_facts, (hashmap_cmp_fn)__name_facts_cmp, NULL, 7);

    return cached_element;
}

static void
__delete_element_facts(struct __cached_element * cached_element, struct hashmap * facts_map)
{
    struct hashmap_iter iter;

    hashmap_iter_init(facts_map, &iter);

    do {
        struct __cached_fact * cached_fact = hashmap_iter_next(&iter);

        if (cached_fact == NULL) {
            break;
        }

        if (cached_fact->is_inserted && !cached_fact->is_rule) {
            if (db_retract_fact(cached_fact)) {
                log_error("retract_db_fact() FAILED\n");
            }
        }

        __free_cached_fact(cached_fact);
    } while (1);

    hashmap_free(facts_map, 0);
}

void
cached_element_free(struct __cached_element * cached_element)
{
    __delete_element_facts(cached_element, &cached_element->uuid_facts);
    __delete_element_facts(cached_element, &cached_element->name_facts);

    nexus_free(cached_element->uuid_str);
    nexus_free(cached_element);
}

struct __cached_fact *
cached_element_put_uuid_fact(struct __cached_element * cached_element,
                             struct nexus_uuid       * uuid,
                             char                    * name,
                             char                    * value)
{
    struct __cached_fact * new_fact = __new_cached_fact(uuid, name, value);

    hashmap_entry_init(new_fact, memhash(&new_fact->uuid, sizeof(struct nexus_uuid)));

    hashmap_add(&cached_element->uuid_facts, &new_fact->hash_entry);

    new_fact->element = cached_element;

    return new_fact;
}


struct __cached_fact *
cached_element_put_name_fact(struct __cached_element * cached_element,
                             char                    * name,
                             char                    * value)
{
    struct __cached_fact * new_fact = __new_cached_fact(NULL, name, NULL);

    hashmap_entry_init(new_fact, strhash(new_fact->name));

    hashmap_add(&cached_element->name_facts, &new_fact->hash_entry);

    new_fact->element = cached_element;

    return new_fact;
}


struct __cached_fact *
cached_element_find_uuid_fact(struct __cached_element * cached_element, struct nexus_uuid * uuid)
{
    struct __cached_fact   tmp_fact = {0};

    nexus_uuid_copy(uuid, &tmp_fact.uuid);
    hashmap_entry_init(&tmp_fact, memhash(&tmp_fact.uuid, sizeof(struct nexus_uuid)));

    return hashmap_get(&cached_element->uuid_facts, &tmp_fact, NULL);
}

struct __cached_fact *
cached_element_find_name_fact(struct __cached_element * cached_element, char * name)
{
    struct __cached_fact   tmp_fact = {0};

    strncpy(&tmp_fact.name, name, ATTRIBUTE_NAME_MAX);
    hashmap_entry_init(&tmp_fact, strhash(tmp_fact.name));

    return hashmap_get(&cached_element->name_facts, &tmp_fact, NULL);
}
