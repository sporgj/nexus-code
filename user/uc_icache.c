#include "uc_icache.h"
#include "uc_dirnode.h"
#include "uc_utils.h"

#include "cdefs.h"

#include "third/hashmap.h"
#include "third/queue.h"
#include "third/sds.h"
#include "third/slog.h"

#include <sys/stat.h>
#include <unistd.h>

struct dirty_item;

typedef struct {
    uc_dirnode_t * dn;
    time_t epoch;
    shadow_t shdw_name;
    uv_mutex_t i_lock; /* locking the whole structure */
    struct dirty_item * dirty_ptr;
} icache_entry_t;

typedef struct dirty_item {
    icache_entry_t * i_entry;
    TAILQ_ENTRY(dirty_item_t) next;
} dirty_item_t;

TAILQ_HEAD(dirty_list_t, dirty_item_t);
static struct dirty_list_t _dirnode_dirty_list,
    *dirnode_dirty_list = &_dirnode_dirty_list;

static uv_mutex_t dirnode_dirty_list_lock;
static size_t dirnode_dirty_list_count = 0;

static Hashmap * dirnode_table;

static int
__hash_dirnode(void * key)
{
    return 0;
}

static uv_timer_t flush_timer;
static uv_thread_t flush_thread;

static void
__flush_dirty_entries()
{
    dirty_item_t *curr, *tvar;
    uc_dirnode_t * dirnode;
    int i = 0, j = 0, k = 0;

    uv_mutex_lock(&dirnode_dirty_list_lock);
    TAILQ_FOREACH_SAFE(curr, dirnode_dirty_list, next, tvar)
    {
        k++;
        dirnode = curr->i_entry->dn;
        // get the lock and flush it to disk
        if (dirnode_trylock(dirnode)) {
            j++;
            uinfo("flush_dirty_entries(): trylock failed %s",
                  dirnode_get_fpath(dirnode));
            continue;
        }

        if (dirnode_fsync(dirnode) == false) {
            goto unlock;
        }

        /* remove it from the list and mark the dirnode clean */
        TAILQ_REMOVE(dirnode_dirty_list, curr, next);
        uv_mutex_lock(&curr->i_entry->i_lock);
        curr->i_entry->dirty_ptr = NULL;
        uv_mutex_unlock(&curr->i_entry->i_lock);

        dirnode_mark_clean(dirnode);
        i++;

        /* free the entry */
        free(curr);
    unlock:
        dirnode_unlock(dirnode);
    }

    uinfo("flush_entries(): size=%zu, flushed=%d, skipped=%d, seen=%d",
          dirnode_dirty_list_count, i, j, k);
    uv_mutex_unlock(&dirnode_dirty_list_lock);
}

static void
start_flush_thread()
{
    uv_loop_t * loop = uv_loop_new();
    uv_loop_init(loop);
    uv_timer_init(loop, &flush_timer);
    uv_timer_start(&flush_timer, __flush_dirty_entries, 5000, 500);
    uv_run(loop, UV_RUN_DEFAULT);
}

int
icache_init()
{
    TAILQ_INIT(dirnode_dirty_list);
    uv_mutex_init(&dirnode_dirty_list_lock);

    uv_thread_create(&flush_thread, start_flush_thread, NULL);
    return 0;
}

void
icache_evict_entry(icache_entry_t * ientry)
{
    uc_dirnode_t * dirnode = ientry->dn;
    dirnode_free(dirnode);
    hashmapRemove(dirnode_table, &ientry->shdw_name);

    if (ientry->dirty_ptr) {
        uv_mutex_lock(&dirnode_dirty_list_lock);
        TAILQ_REMOVE(&dirnode_dirty_list, ientry->dirty_ptr, next);
        uv_mutex_lock(&ientry->i_lock);
        ientry->dirty_ptr = NULL;
        uv_mutex_unlock(&ientry->i_lock);
        uv_mutex_unlock(&dirnode_dirty_list_lock);
    }
}

/**
 * adds the dirnode to the dirty list
 */
void
icache_dirty_dirnode(uc_dirnode_t * dirnode, const shadow_t * shdw_name)
{
    dirty_item_t * dirty_item;
    icache_entry_t * i_entry;
    i_entry = (icache_entry_t *)hashmapGet(dirnode_table, (void *)shdw_name);
    if (i_entry == NULL) {
        return;
    }

    dirty_item = (dirty_item_t *)malloc(sizeof(dirty_item_t));
    if (dirty_item) {
        slog(0, SLOG_ERROR, "allocation error");
        return;
    }

    /* add it to the dirty list */
    uv_mutex_lock(&dirnode_dirty_list_lock);

    /* update the pointers */
    uv_mutex_lock(&i_entry->i_lock);
    i_entry->dirty_ptr = dirty_item;
    dirty_item->i_entry = i_entry;
    uv_mutex_unlock(&i_entry->i_lock);

    TAILQ_INSERT_TAIL(dirnode_dirty_list, dirty_item, next);
    uv_mutex_unlock(&dirnode_dirty_list_lock);
}

static int
icache_add_dirnode(uc_dirnode_t * dirnode, const shadow_t * shdw_name)
{
    int * hashval;
    icache_entry_t * i_entry = (icache_entry_t *)malloc(sizeof(icache_entry_t));
    if (i_entry == NULL) {
        slog(0, SLOG_ERROR, "memory allocation failed");
        return -1;
    }

    i_entry->dn = dirnode;
    i_entry->epoch = time(NULL);
    memcpy(&i_entry->shdw_name, shdw_name, sizeof(shadow_t));
    uv_mutex_init(&i_entry->i_lock);

    if (hashmapPut(dirnode_table, (void *)shdw_name, i_entry, &hashval)
        == NULL) {
        slog(0, SLOG_ERROR, "could not add entry to dirnode");
        return -1;
    }

    return 0;
}

uc_dirnode_t *
icache_get_dirnode(const shadow_t * shdw_name)
{
    icache_entry_t * i_entry;
    uc_dirnode_t * dirnode = NULL;
    struct stat st;
    int * hashval;
    sds fpath;

    /* 1 - check if it's in the cache */
    i_entry = (icache_entry_t *)hashmapGet(dirnode_table, (void *)shdw_name);
    if (i_entry == NULL) {
        goto load_from_disk;
    }

    /* 2 - if found, check if the on-disk copy is up to date */
    dirnode = i_entry->dn;
    fpath = (sds) dirnode_get_fpath(dirnode);
    if (stat(fpath, &st)) {
        slog(0, SLOG_ERROR, "could not stat: %s", fpath);
        goto out;
    }

    // if the the on-disk copy is newer, reload everything
    if (difftime(st.st_mtime, i_entry->epoch) > 0) {
        icache_evict_entry(i_entry);
        free(i_entry);
        goto load_from_disk;
    }

    // just return the dirnode
    goto out;

/* 3 - not found, load from disk and add to dirnode */
load_from_disk:
    dirnode = dirnode_from_shadow_name(shdw_name);
    if (dirnode == NULL) {
        goto out;
    }

    if (icache_add_dirnode(dirnode, shdw_name)) {
        goto cleanup;
    }

out:
    return dirnode;

cleanup:
    dirnode_free(dirnode);
    return NULL;
}
