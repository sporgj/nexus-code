/**
 * Handles the caching of metadata items
 *
 * @author Judicael Briand
 */
#include "uc_metadata.h"
#include "uc_utils.h"

#include "third/hashmap.h"
#include "third/queue.h"
#include "third/sds.h"
#include "third/slog.h"

#include <sys/stat.h>
#include <unistd.h>

#include <string.h>

#include <uv.h>

struct dirty_item;

typedef struct metadata_entry {
    uc_dirnode_t * dn;
    time_t epoch;
    shadow_t shdw_name; // XXX not necessary, can get it from dirnode
    struct dirty_item * dirty_item;
    uv_mutex_t lock; /* locking the whole structure */
} metadata_entry_t;

typedef struct dirty_item {
    metadata_entry_t * entry;
    TAILQ_ENTRY(dirty_item) next_item;
} dirty_item_t;

/* our lists */
TAILQ_HEAD(dirty_list_t, dirty_item);

static struct dirty_list_t _l, *dirty_list_head = &_l;
static uv_mutex_t dirty_list_lock;
static size_t dirty_list_count = 0;

static Hashmap * metadata_hashmap;

int
metadata_dirty_dirnode(uc_dirnode_t * dn)
{
    metadata_entry_t * entry = dirnode_get_metadata(dn);
    // XXX assert(entry != NULL)

    /* create the list entry and add our new guy */
    dirty_item_t * dirty_item = (dirty_item_t *)malloc(sizeof(dirty_item_t));
    if (dirty_item == NULL) {
        slog(0, SLOG_ERROR, "could not create new entry for the dirty item");
        // TODO remove item from the cache?
        return -1;
    }

    dirty_item->entry = entry;

    uv_mutex_lock(&entry->lock);
    entry->dirty_item = dirty_item;
    uv_mutex_unlock(&entry->lock);

    /* add it to the dirty list */
    uv_mutex_lock(&dirty_list_lock);
    TAILQ_INSERT_TAIL(dirty_list_head, dirty_item, next_item);
    dirty_list_count++;
    uv_mutex_unlock(&dirty_list_lock);

    return 0;
}

static int
_create_entry(uc_dirnode_t * dn, const shadow_t * shdw)
{
    int ret = -1, *hash;
    void * ptr;
    metadata_entry_t * entry
        = (metadata_entry_t *)malloc(sizeof(metadata_entry_t));
    if (entry == NULL) {
        slog(0, SLOG_ERROR, "allocation failed for metadata_entry_t");
        return -1;
    }

    entry->dn = dn;
    entry->epoch = time(NULL);
    memcpy(&entry->shdw_name, shdw, sizeof(shadow_t));
    entry->dirty_item = NULL;
    uv_mutex_init(&entry->lock);

    dirnode_set_metadata(dn, entry);

    // add it to the hashmap
    hashmapLock(metadata_hashmap);
    ptr = hashmapPut(metadata_hashmap, (void *)shdw, entry, &hash);
    hashmapUnlock(metadata_hashmap);

    if (ptr == NULL) {
        slog(0, SLOG_ERROR, "hashmapPut returned NULL");
        goto out;
    }

    ret = 0;
out:
    if (ret) {
        free(entry);
    }

    return ret;
}

static void
_evict_entry(metadata_entry_t * entry)
{
    void * ptr;

    hashmapLock(metadata_hashmap);
    ptr = hashmapGet(metadata_hashmap, (void *)&entry->shdw_name);
    hashmapUnlock(metadata_hashmap);
    // TODO check for the value of ptr

    dirnode_free(entry->dn);

    uv_mutex_lock(&dirty_list_lock);
    uv_mutex_lock(&entry->lock);
    if (entry->dirty_item) {
        TAILQ_REMOVE(dirty_list_head, entry->dirty_item, next_item);
        dirty_list_count--;
    }
    uv_mutex_unlock(&entry->lock);
    uv_mutex_unlock(&dirty_list_lock);

    free(entry);
}

uc_dirnode_t *
metadata_get_dirnode(const shadow_t * shadow_name)
{
    uc_dirnode_t * dn = NULL;
    metadata_entry_t * entry;
    struct stat st;
    int * hashval;
    sds fpath;

    /* check if the item is in the cache */
    entry
        = (metadata_entry_t *)hashmapGet(metadata_hashmap, (void *)shadow_name);
    if (entry == NULL) {
        goto load_from_disk;
    }

    /* if found, check the on-disk time */
    if (difftime(st.st_mtime, entry->epoch) > 0) {
        _evict_entry(entry);
        goto load_from_disk;
    }

    /* we found the dirnode, and it's the latest version */
    dn = entry->dn;
    goto out;

load_from_disk:
    dn = dirnode_from_shadow_name(shadow_name);
    if (dn == NULL) {
        goto out;
    }

    // add it to the metadata cache
    if (_create_entry(dn, shadow_name)) {
        goto cleanup;
    }

out:
    return dn;

cleanup:
    dirnode_free(dn);
    return NULL;
}

static void
metadata_flush()
{
    int i = 0, j = 0, k = 0;
    uc_dirnode_t * dn;
    metadata_entry_t * entry;
    dirty_item_t *var, *tvar;

    uv_mutex_lock(&dirty_list_lock);
    TAILQ_FOREACH_SAFE(var, dirty_list_head, next_item, tvar)
    {
        k++;
        entry = var->entry, dn = entry->dn;

        if (dirnode_trylock(dn)) {
            j++;
            continue;
        }

        if (dirnode_fsync(dn) == false) {
            goto unlock;
        }

        /* remove it from the dirty list */
        TAILQ_REMOVE(dirty_list_head, var, next_item);
        uv_mutex_lock(&entry->lock);
        entry->dirty_item = NULL;
        uv_mutex_unlock(&entry->lock);

        i++;
        free(var);
    unlock:
        dirnode_unlock(dn);
    }

    dirty_list_count -= i;
    printf(":: flush_entries(): size=%zu, flushed=%d, skipped=%d, seen=%d",
           dirty_list_count, i, j, k);
    uv_mutex_unlock(&dirty_list_lock);
}

static uv_timer_t flush_timer;
static uv_thread_t flush_thread;

static void
start_flush_thread()
{
    uv_loop_t * loop = uv_loop_new();
    uv_loop_init(loop);
    uv_timer_init(loop, &flush_timer);
    uv_timer_start(&flush_timer, metadata_flush, 5000, 500);
    uv_run(loop, UV_RUN_DEFAULT);
}

static int
_hash_func(void * key)
{
    return murmurhash((char *)key, sizeof(shadow_t), 0);
}

static bool
_hash_eq(void * ka, void * kb)
{
    return memcmp(ka, kb, sizeof(shadow_t)) == 0;
}

int
metadata_init()
{
    metadata_hashmap = hashmapCreate(64, _hash_func, _hash_eq);
    if (metadata_hashmap == NULL) {
        slog(0, SLOG_ERROR, "hashmapCreate returns NULL");
        return -1;
    }

    TAILQ_INIT(dirty_list_head);

	// add the default dnode to the cache
	if (metadata_get_dirnode(&uc_root_dirnode_shadow_name)) {
		slog(0, SLOG_ERROR, "metadata_get_dirnode root failed");
		return -1;
	}

    uv_thread_create(&flush_thread, start_flush_thread, NULL);

    return 0;
}
