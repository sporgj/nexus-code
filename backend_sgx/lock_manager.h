/**
 * Manages the locking of metadata files on disk
 *
 * @author Judicael Briand Djoko
 */

#include <nexus_file_handle.h>

struct lock_manager;

struct __locked_uuid {
    struct nexus_uuid           uuid;

    struct nexus_file_handle  * file_handle;
};


struct lock_manager *
lock_manager_init();

void
lock_manager_destroy(struct lock_manager * lock_manager);

/**
 * Adds a new UUID to the lock manager
 * @param lock_manager
 * @param uuid
 * @return 0 on success
 */
int
lock_manager_add(struct lock_manager      * lock_manager,
                 struct nexus_uuid        * uuid,
                 struct nexus_file_handle * file_handle);

/**
 * Returns the raw file associated with a UUID
 * @param lock_manager
 * @param uuid
 * @return NULL on failure
 */
struct nexus_file_handle *
lock_manager_find(struct lock_manager * lock_manager, struct nexus_uuid * uuid);

/**
 * Removes UUID from the lock manager
 */
struct nexus_file_handle *
lock_manager_del(struct lock_manager * lock_manager, struct nexus_uuid * uuid);
