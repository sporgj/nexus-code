/**
 * Handles the caching of metadata items
 *
 * @author Judicael Briand
 */
#include "uc_utils.h"
#include "uc_vfs.h"

#include "third/hashmap.h"
#include "third/queue.h"
#include "third/sds.h"
#include "third/slog.h"
#include "third/log.h"

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

void
metadata_update_entry(struct metadata_entry * entry)
{
    entry->epoch = time(NULL);
}

uc_dirnode_t *
metadata_root_dirnode(const char * path)
{
    return metadata_get_dirnode(path, vfs_root_dirnode(path));
}

uc_dirnode_t *
metadata_get_dirnode(const char * path, const shadow_t * shadow_name)
{
    uc_dirnode_t * dn = NULL;
    metadata_entry_t * entry;
    struct stat st;
    int * hashval;
    sds fpath = NULL;

    /* check if the item is in the cache */
    entry
        = (metadata_entry_t *)hashmapGet(metadata_hashmap, (void *)shadow_name);
    if (entry == NULL) {
        goto load_from_disk;
    }

    /* if found, check the on-disk time */
    if ((fpath = vfs_metadata_path(path, shadow_name)) == NULL) {
        log_error("vfs_metadata_path returned NULL (%s)", fpath);
        goto out;
    }

    if (stat(fpath, &st)) {
        log_error("file '%s' does not exist", fpath);
        goto out;
    }

    if (difftime(st.st_mtime, entry->epoch) > 0) {
        // implicitly deletes the dirnode object
        _evict_entry(entry);
        goto load_from_disk;
    }

    /* we found the dirnode, and it's the latest version */
    dn = entry->dn;
    goto out;

load_from_disk:
    if (fpath == NULL
        && (fpath = vfs_metadata_path(path, shadow_name)) == NULL) {
        log_error("vfs_metadata_path returned NULL (%s)", fpath);
        goto out;
    }

    /* load it from disk */
    if ((dn = dirnode_from_file(fpath)) == NULL) {
        goto out;
    }

    // add it to the metadata cache
    if (_create_entry(dn, shadow_name)) {
        dirnode_free(dn);
        dn = NULL;
    }

out:
    if (fpath) {
        sdsfree(fpath);
    }

    return dn;
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

    return 0;
}

void
metadata_exit()
{
    // TODO clear all data here
}
