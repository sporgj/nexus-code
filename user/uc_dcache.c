#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "third/hashmap.h"
#include "third/log.h"
#include "third/queue.h"
#include "third/selist.h"

#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_uspace.h"
#include "uc_utils.h"
#include "uc_vfs.h"

unsigned long
crc32(const unsigned char * s, unsigned int len);

void
dcache_add(struct uc_dentry * dentry, struct uc_dentry * parent);

struct uc_dentry *
dcache_new(const char * name,
           const shadow_t * dirnode_name,
           const struct uc_dentry * parent,
           struct dentry_tree * dentry_tree);

/* for statistics */
uint64_t stats_total_cache_entries = 0;
uint64_t stats_cache_hits = 0;
uint64_t stats_cache_misses = 0;
uint64_t stats_cache_lookups = 0;

uv_timer_t stats_timer;
uv_thread_t stats_thread;

int
hash_dentry(void * p_dcache_key)
{
    return hash_string(((dcache_key_t *)p_dcache_key)->name);
}

bool
hash_is_equals(void * keyA, void * keyB)
{
    dcache_key_t *da = (dcache_key_t *)keyA, *db = (dcache_key_t *)keyB;
    return da->parent == db->parent && strcmp(da->name, db->name) == 0;
}

void
print_dcache_stats(uv_timer_t * handle)
{
    printf("\n------------------ DCACHE STATS -------------------");
    printf("\n references: %lu, misses: %lu, hits: %lu", stats_cache_lookups,
           stats_cache_misses, stats_cache_hits);
    printf("\n---------------------------------------------------\n");
}

static void
start_stats_thread()
{
    uv_loop_t * loop = uv_loop_new();
    uv_loop_init(loop);
    uv_timer_init(loop, &stats_timer);
    uv_timer_start(&stats_timer, print_dcache_stats, 5000, 10000);
    uv_run(loop, UV_RUN_DEFAULT);
}

struct dentry_tree *
dcache_new_root(shadow_t * root_shdw, const char * path)
{
    int err = -1;
    sds root_path;
    struct dentry_tree * tree = NULL;
    if ((tree = calloc(1, sizeof(struct dentry_tree))) == NULL) {
        log_fatal("allocation failed");
        return NULL;
    }

    tree->hashmap = hashmapCreate(MAP_INIT_SIZE, hash_dentry, hash_is_equals);
    tree->root_dentry = dcache_new("", root_shdw, NULL, tree);
    if (tree->root_dentry == NULL) {
        log_fatal("allocation failed");
        goto out;
    }

    root_path = sdsnew(path);
    root_path = sdscat(root_path, "/");
    root_path = sdscat(root_path, UCAFS_WATCH_DIR);
    tree->root_path = root_path;

    sds afsx_path = sdsnew(path);
    afsx_path = sdscat(afsx_path, "/");
    afsx_path = sdscat(afsx_path, UCAFS_REPO_DIR);
    tree->afsx_path = afsx_path;

    uv_mutex_init(&tree->dcache_lock);

    dcache_add(tree->root_dentry, NULL);

    err = 0;
out:
    if (err) {
        if (tree->root_dentry) {
            free(tree->root_dentry);
        }

        if (tree->hashmap) {
            hashmapFree(tree->hashmap);
        }

        free(tree);
        tree = NULL;
    }

    return tree;
}

void
dcache_exit()
{
    // TODO clear variables and exit timers here
}

struct uc_dentry *
dcache_new(const char * name,
           const shadow_t * dirnode_name,
           const struct uc_dentry * parent,
           struct dentry_tree * dentry_tree)
{
    struct uc_dentry * dentry;
    dentry = (struct uc_dentry *)calloc(1, sizeof(struct uc_dentry));
    if (dentry == NULL) {
        log_fatal("allocation error on new uc_dentry");
        return NULL;
    }

    memcpy(&dentry->shdw_name, dirnode_name, sizeof(shadow_t));
    dentry->key.parent = parent;
    dentry->key.name = sdsnew(name);
    dentry->valid = 1;
    dentry->dentry_tree = dentry_tree;
    uv_mutex_init(&dentry->v_lock);
    uv_mutex_init(&dentry->c_lock);

    /* initialize the list and return the pointer */
    SLIST_INIT(&dentry->children);

    return dentry;
}

// deletes the dentry as well as its children
void
dcache_free(struct uc_dentry * dentry)
{
    dcache_item_t * ptr_entry;
    Hashmap * hashmap = dentry->dentry_tree->hashmap;

    /* deallocate the children */
    uv_mutex_lock(&dentry->c_lock);
    while (!SLIST_EMPTY(&dentry->children)) {
        /* get the head, remove its children and then remove it */
        ptr_entry = SLIST_FIRST(&dentry->children);

        dcache_free(ptr_entry->dentry);

        SLIST_REMOVE_HEAD(&dentry->children, next_dptr);
        free(ptr_entry);
    }
    uv_mutex_unlock(&dentry->c_lock);

    hashmapLock(hashmap);
    hashmapRemove(hashmap, &dentry->key);
    stats_total_cache_entries--;
    hashmapUnlock(hashmap);

    sdsfree(dentry->key.name);
    memset(dentry, 0, sizeof(struct uc_dentry));
    free(dentry);
}

void
dcache_add(struct uc_dentry * dentry, struct uc_dentry * parent)
{
    Hashmap * hashmap = dentry->dentry_tree->hashmap;
    dcache_item_t * entry = (dcache_item_t *)malloc(sizeof(dcache_item_t));
    if (entry == NULL) {
        log_warn("allocation on new dlist_item");
        return;
    }

    entry->dentry = dentry;

    if (parent) {
        uv_mutex_lock(&parent->c_lock);
        /* add the entry to the parent's children */
        SLIST_INSERT_HEAD(&parent->children, entry, next_dptr);
        uv_mutex_unlock(&parent->c_lock);
    }

    /* add it to the hashmap */
    /* TODO hashmapPut returns the exisiting hash value if we have a
     * matching entry */
    hashmapPut(hashmap, &dentry->key, dentry, &dentry->key.p_hashval);

    // TODO add lock
    stats_total_cache_entries++;
}

struct uc_dentry *
hash_lookup(const struct uc_dentry * parent, const char * name)
{
    Hashmap * hashmap = parent->dentry_tree->hashmap;
    dcache_key_t v = {.parent = parent, .name = (const sds)name };

    struct uc_dentry * dentry = (struct uc_dentry *)hashmapGet(hashmap, &v);

    stats_cache_lookups++;
    if (dentry && dentry->valid) {
        stats_cache_hits++;
        return dentry;
    }

    stats_cache_misses++;
    return NULL;
}

/**
 * The main traversal procedure
 * @param parent_dentry is where we start traversing from
 * @param canonical_path is the absolute path of the item we want
 * @param path_cstr is the path to traverse from the dentry
 * @param p_dest_dn, the destination dirnode object
 * @return NULL if the dentry is not found
 */
static struct uc_dentry *
dcache_traverse(struct uc_dentry * parent_dentry,
                path_builder_t * path_build,
                char * path_cstr)
{
    int jrnl;
    struct uc_dentry * dentry;
    ucafs_entry_type atype;
    char *nch, *pch;
    const link_info_t * link_info;
    const shadow_t * shdw;
    uc_dirnode_t * dn = NULL;
    struct path_element * path_elmt;

    /* start tokenizing */
    nch = strtok_r(path_cstr, "/", &pch);

    while (nch) {
        link_info = NULL;

        if (nch[0] == '.') {
            if (nch[1] == '\0') {
                // then let's skip to the next one
                goto next;
            }

            if (nch[1] == '.' && nch[2] == '\0') {
                // move up by one parent_dentry and go to the next
                dentry = (struct uc_dentry *)parent_dentry->key.parent;
                if (dentry == NULL) {
                    break;
                }

                // TODO check return
                path_elmt = TAILQ_LAST(path_build, path_builder);
                TAILQ_REMOVE(path_build, path_elmt, next_entry);
                free(path_elmt);

                goto next1;
            }
        }

        /* 1 - hash_lookup: checks if the entry was already created */
        if ((dentry = hash_lookup(parent_dentry, nch))) {
            // TODO ask the metadata to check for up-to-date information
            /* let's jump to the next one */
            goto next1;
        }

        /* 2 - Fetch the parent dirnode from disk */
        if ((dn = metadata_get_dirnode(path_build, parent_dentry)) == NULL) {
            break;
        }

        /* 3 - load the shadow name of the new dentry */
        shdw = dirnode_traverse(dn, nch, UC_ANY, &atype, &jrnl, &link_info);
        if (shdw == NULL || atype == UC_FILE) {
            break;
        }

        /* special care for our symlinks :( */
        if (atype == UC_LINK) {
            /* get the link and recursively traverse */
            char * link_cstr = strdup(link_info->target_link);
            dentry = dcache_traverse(parent_dentry, path_build, link_cstr);
            free(link_cstr);

            if (dentry) {
                goto next1;
            }
        }

        /* 4 - now create the new entry */
        dentry
            = dcache_new(nch, shdw, parent_dentry, parent_dentry->dentry_tree);
        if (dentry == NULL) {
            log_error("dcache_new returned NULL");
            break;
        }

        /* minor optimisation to prevent iterating the parent dirnode entries
         * many times */
        dentry->negative = (jrnl != JRNL_NOOP);

        dcache_add(dentry, parent_dentry);

    next1:
        /* only add to the path if it's not the root path */
        if (parent_dentry) {
            path_elmt = (struct path_element *)malloc(sizeof(struct path_element));
            if (path_elmt == NULL) {
                log_fatal("allocation error");
                return NULL;
            }

            path_elmt->shdw = (shadow_t *)&dentry->shdw_name;
            TAILQ_INSERT_TAIL(path_build, path_elmt, next_entry);
        }

        /* move the path to the next component */
        parent_dentry = dentry;

    next:
        nch = strtok_r(NULL, "/", &pch);
    }

    /* now return the entry */
    /* if it's not null, it means we haven't parsed to the end of the string */
    if (nch) {
        return NULL;
    }

    return dentry;
}

static void
free_path_builder(path_builder_t * path_build)
{
    struct path_element * path_elmt;

    while ((path_elmt = TAILQ_FIRST(path_build))) {
        TAILQ_REMOVE(path_build, path_elmt, next_entry);
        free(path_elmt);
    }
}

/**
 * Performs a lookup of the corresponding path
 * @param path is the full file path
 * @param dirpath just the parent or the child directory
 * return the corresponding uc_dentry, else NULL if not found
 */
static inline uc_dirnode_t *
_dcache_lookup(struct dentry_tree * tree,
               path_builder_t * path_build,
               struct uc_dentry ** pp_dentry,
               const char * path,
               bool dirpath)
{
    struct uc_dentry * dentry;
    uc_dirnode_t * dirnode = NULL;
    sds relpath;

    if ((relpath = vfs_relpath(path, dirpath)) == NULL) {
        log_warn("getting relpath `%s` FAILED", path);
        return NULL;
    }

    /* if we are NOT looking up the root dentry */
    if (strlen(relpath)) {
        dentry = dcache_traverse(tree->root_dentry, path_build, relpath);
    } else {
        dentry = tree->root_dentry;
    }

    if (dentry && (dirnode = metadata_get_dirnode(path_build, dentry))) {
        atomic_fetch_add(&dentry->count, 1);
        dirnode_set_dentry(dirnode, dentry);
    }

    *pp_dentry = dentry;
done:
    sdsfree(relpath);
    return dirnode;
}

uc_dirnode_t *
dcache_lookup(struct dentry_tree * tree, const char * path, bool dirpath)
{
    struct uc_dentry * dentry;
    path_builder_t path_list;

    TAILQ_INIT(&path_list);
    uc_dirnode_t * dirnode
        = _dcache_lookup(tree, &path_list, &dentry, path, dirpath);
    free_path_builder(&path_list);

    return dirnode;
}

uc_filebox_t *
dcache_get_filebox(struct dentry_tree * tree,
                   const char * path,
                   size_t size_hint)
{
    int err, jrnl;
    const shadow_t * shdw;
    char *fname = NULL, *temp = NULL, *temp2 = NULL;
    sds path_link = NULL, fbox_path = NULL;
    ucafs_entry_type atype;
    const link_info_t * link_info = NULL;
    uc_filebox_t * fb = NULL;
    struct uc_dentry * dentry;
    path_builder_t path_list;
    uc_dirnode_t * dirnode;

    TAILQ_INIT(&path_list);

    dirnode = _dcache_lookup(tree, &path_list, &dentry, path, false);
    if (dirnode == NULL) {
        return NULL;
    }

    if ((fname = do_get_fname(path)) == NULL) {
        return NULL;
    }

    /* get the entry in the file */
    shdw = dirnode_traverse(dirnode, fname, UC_ANY, &atype, &jrnl, &link_info);
    if (shdw == NULL) {
        goto out;
    }

    /* if we are loading a link, then the codename should point to its info */
    if (link_info) {
        if (link_info->type == UC_HARDLINK) {
            shdw = &link_info->meta_file;
        } else {
            // we have to traverse here
            if (link_info->target_link[0] == '/') {
                // we have an absolute path
                // send request here
                fb = dcache_get_filebox(tree, link_info->target_link, size_hint);
                goto out;
            } else {
                // have an relative path
                path_link = do_get_dir(path);
                path_link = sdscat(path_link, "/");
                path_link = sdscat(path_link, link_info->target_link);

                fb = dcache_get_filebox(tree, path_link, size_hint);
                sdsfree(path_link);
                goto out;
            }
        }
    }

    fb = metadata_get_filebox(dentry, dirnode, &path_list, shdw, size_hint,
                              jrnl);
out:
    sdsfree(fbox_path);

    if (link_info) {
        free((link_info_t *)link_info);
    }

    free_path_builder(&path_list);

    // TODO put dirnode

    sdsfree(fname);
    return fb;
}

void
dcache_put(uc_dirnode_t * dn)
{
    // container of
    struct uc_dentry * dentry = (struct uc_dentry *)dirnode_get_dentry(dn);
    atomic_fetch_sub(&dentry->count, 1);

    if (dentry->count < 0) {
        log_warn("dentry ref count is negative (%d)", dentry->count);
        return;
    }

    // TODO add mutiple links to single dentry object
}

/**
 * Keep in mind, this doesn't remove the dirnode.
 * Uses the dirnode's dentry to find the entry in the hash and remove it
 */
void
dcache_rm(uc_dirnode_t * dn, const char * entry_name)
{
    struct uc_dentry *parent = (struct uc_dentry *)dirnode_get_dentry(dn),
                     *child;
    dcache_item_t *prev = NULL, *curr, *next;
    dcache_key_t temp_key = {.parent = parent, .name = (const sds)entry_name };
    Hashmap * hashmap = parent->dentry_tree->hashmap;
    int hash_val = hashmapHashKey(hashmap, &temp_key);

    if (parent == NULL) {
        return;
    }

    // remove the entry from the parent
    SLIST_FOREACH_SAFE(curr, &parent->children, next_dptr, next)
    {
        child = curr->dentry;
        /* perform a hash comparison for a fast check */
        if (hash_val == *child->key.p_hashval
            && strcmp(entry_name, child->key.name) == 0) {
            /* free the memory */
            if (prev == NULL) {
                SLIST_REMOVE_HEAD(&parent->children, next_dptr);
            } else {
                SLIST_REMOVE_AFTER(prev, next_dptr);
            }

            dcache_free(child);
            free(curr);
            break;
        }

        prev = curr;
    }
}
