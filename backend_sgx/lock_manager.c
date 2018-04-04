#include "internal.h"

#include <nexus_hashtable.h>


#define HASHTABLE_SIZE 127

struct lock_manager {
    size_t                   count;

    struct nexus_hashtable * htable;
};

struct __locked_uuid {
    struct nexus_uuid       uuid;

    struct nexus_raw_file * raw_file;
};

struct lock_manager *
lock_manager_init()
{
    struct lock_manager * lock_manager = NULL;

    lock_manager = nexus_malloc(sizeof(struct lock_manager));

    lock_manager->htable = nexus_create_htable(HASHTABLE_SIZE, uuid_hash_func, uuid_equal_func);

    if (lock_manager->htable == NULL) {
        nexus_free(lock_manager);

        log_error("could not allocate hashtable\n");
        return NULL;
    }

    return lock_manager;
}

void
lock_manager_destroy(struct lock_manager * lock_manager)
{
    nexus_free_htable(lock_manager->htable, 1, 0);
}

int
lock_manager_add(struct lock_manager   * lock_manager,
                 struct nexus_uuid     * uuid,
                 struct nexus_raw_file * raw_file)
{
    struct __locked_uuid * locked_uuid = NULL;

    int ret = -1;


    locked_uuid = nexus_htable_search(lock_manager->htable, (uintptr_t)uuid);

    if (locked_uuid != NULL) {
        log_error("locked uuid already in hashtable\n");
        return -1;
    }

    locked_uuid = nexus_malloc(sizeof(struct __locked_uuid));

    nexus_uuid_copy(uuid, &locked_uuid->uuid);

    locked_uuid->raw_file = raw_file;

    ret = nexus_htable_insert(lock_manager->htable,
                              (uintptr_t)&locked_uuid->uuid,
                              (uintptr_t)locked_uuid);

    if (ret == 0) {
        log_error("could not insert item into lock_manager\n");
        return -1;
    }

    return 0;
}

struct nexus_raw_file *
lock_manager_drop(struct lock_manager * lock_manager, struct nexus_uuid * uuid)
{
    struct __locked_uuid  * locked_uuid = NULL;

    struct nexus_raw_file * raw_file    = NULL;


    locked_uuid = (struct __locked_uuid *)nexus_htable_remove(lock_manager->htable,
                                                              (uintptr_t)uuid,
                                                              0);

    if (locked_uuid == NULL) {
        return NULL;
    }

    raw_file = locked_uuid->raw_file;

    nexus_free(locked_uuid);

    return raw_file;
}

struct nexus_raw_file *
lock_manager_get(struct lock_manager * lock_manager, struct nexus_uuid * uuid)
{
    struct __locked_uuid  * locked_uuid = NULL;

    locked_uuid = (struct __locked_uuid *) nexus_htable_search(lock_manager->htable, (uintptr_t)uuid);

    if (locked_uuid) {
        return locked_uuid->raw_file;
    }

    return NULL;
}
