#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "third/hashmap.h"
#include "third/log.h"
#include "third/queue.h"
#include "third/slog.h"

#include "uc_vfs.h"
#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_metadata.h"
#include "uc_uspace.h"
#include "uc_utils.h"

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
dcache_new_root(shadow_t * root_shdw)
{
    int err = -1;
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
        slog(0, SLOG_ERROR, "allocation error on new uc_dentry");
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
        slog(0, SLOG_ERROR, "allocation on new dlist_item");
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
traverse(struct uc_dentry * root_dentry,
         struct uc_dentry * parent_dentry,
         const char * canonical_path,
         char * path_cstr,
         uc_dirnode_t ** p_dest_dn)
{
    struct uc_dentry * dentry = parent_dentry;
    ucafs_entry_type atype;
    char *metaname_str, *nch, *pch;
    const link_info_t * link_info;
    const shadow_t * shadow_name;
    uc_dirnode_t *dn = NULL, *alias_dn = NULL;
    bool found_in_cache;

    /* start tokenizing */
    nch = strtok_r(path_cstr, "/", &pch);

    while (nch) {
        link_info = NULL;

        if (nch[0] == '.') {
            if (nch[1] == '\0') {
                // then let's skip to the next one
                goto next1;
            }

            if (nch[1] == '.' && nch[2] == '\0') {
                // move up by one parent_dentry and go to the next
                dentry = (struct uc_dentry *)parent_dentry->key.parent;
                if (dentry == NULL) {
                    break;
                }

                goto next1;
            }
        }

        /* 1 - hash_lookup */
        if ((dentry = hash_lookup(parent_dentry, nch))) {
            found_in_cache = true;
            /* let's jump to the next one */
            shadow_name = &dentry->shdw_name;
            goto next;
        }

        /* 2 - We have to do a real fetch from disk */
        if (dn == NULL) {
            if (parent_dentry == root_dentry) {
                dn = metadata_root_dirnode(canonical_path);
            } else {
                dn = metadata_get_dirnode(canonical_path,
                                          &parent_dentry->shdw_name);
            }

            if (dn == NULL) {
                break;
            }
        }

        shadow_name = dirnode_traverse(dn, nch, UC_ANY, &atype, &link_info);
        if (shadow_name == NULL || atype == UC_FILE) {
            break;
        }

        /* special care for our symlinks :( */
        if (atype == UC_LINK) {
            /* get the link and recursively traverse */
            char * link_cstr = strdup(link_info->target_link);
            dentry = traverse(root_dentry, parent_dentry, canonical_path,
                              link_cstr, &dn);
            free(link_cstr);

            if (dentry) {
                goto next1;
            }
        }

        found_in_cache = false;
    next:
        /* get the path to the dnode */
        if (found_in_cache == false) {
            alias_dn = dn;
            dn = metadata_get_dirnode(canonical_path, shadow_name);
            if (dn == NULL) {
                break;
            }

            /* lets add the entry to the dirnode */
            dentry = dcache_new(nch, shadow_name, parent_dentry,
                                parent_dentry->dentry_tree);
            if (dentry == NULL) {
                log_error("dcache_new returned NULL");
                break;
            }

            dcache_add(dentry, parent_dentry);
        }

        if (alias_dn) {
            alias_dn = NULL;
        }
    next1:
        parent_dentry = dentry;
        nch = strtok_r(NULL, "/", &pch);
    }

    /* now return the entry */
    if (nch == NULL) {
        *p_dest_dn = (dn == NULL)
            ? metadata_get_dirnode(canonical_path, &parent_dentry->shdw_name)
            : dn;
        return dentry;
    }

    *p_dest_dn = NULL;
    return NULL;
}

static struct uc_dentry *
real_lookup(struct uc_dentry * root_dentry,
            const char * canonical_path,
            const char * rel_path,
            uc_dirnode_t ** dn)
{
    /* first, lets get the parent dnode */
    struct uc_dentry * result_dentry;
    char * path_cstr = strdup(rel_path);

    result_dentry
        = traverse(root_dentry, root_dentry, canonical_path, path_cstr, dn);

    free(path_cstr);
    return result_dentry;
}

/**
 * Performs a lookup of the corresponding path
 * @param path is the full file path
 * @param dirpath just the parent or the child directory
 * return the corresponding uc_dentry, else NULL if not found
 */
uc_dirnode_t *
dcache_lookup(struct dentry_tree * tree, const char * path, bool dirpath)
{
    struct uc_dentry * dentry = tree->root_dentry;
    uc_dirnode_t * dirnode = NULL;
    char * temp;
    sds temp_path, relpath;

    if ((relpath = vfs_relpath(path, dirpath)) == NULL) {
        slog(0, SLOG_ERROR, "getting relpath `%s` FAILED", path);
        return NULL;
    }

    // just return the root dirnode
    if (strlen(relpath)) {
        dentry = real_lookup(dentry, path, relpath, &dirnode);
    } else {
        dirnode = metadata_root_dirnode(path);
    }

    /* increase the ref count */
    if (dentry && dirnode) {
        atomic_fetch_add(&dentry->count, 1);
        dirnode_set_dentry(dirnode, dentry);
    }

done:
    sdsfree(relpath);
    return dirnode;
}

uc_filebox_t *
dcache_get_filebox(struct dentry_tree * tree, const char * path, size_t hint)
{
    const shadow_t * codename;
    char *fname = NULL, *temp = NULL, *temp2 = NULL;
    sds path_link = NULL, fbox_path = NULL;
    ucafs_entry_type atype;
    const link_info_t * link_info = NULL;
    uc_filebox_t * fb = NULL;
    uc_dirnode_t * dirnode = dcache_lookup(tree, path, false);

    if (dirnode == NULL) {
        return NULL;
    }

    if ((fname = do_get_fname(path)) == NULL) {
        return NULL;
    }

    /* get the entry in the file */
    codename = dirnode_traverse(dirnode, fname, UC_ANY, &atype, &link_info);
    if (codename == NULL) {
        goto out;
    }

    /* if we are loading a link, then the codename should point to its info */
    if (link_info) {
        if (link_info->type == UC_HARDLINK) {
            codename = &link_info->meta_file;
        } else {
            // we have to traverse here
            if (link_info->target_link[0] == '/') {
                // we have an absolute path
                // send request here
                fb = dcache_get_filebox(tree, link_info->target_link, hint);
                goto out;
            } else {
                // have an relative path
                path_link = do_get_dir(path);
                path_link = sdscat(path_link, "/");
                path_link = sdscat(path_link, link_info->target_link);
                temp2 = do_absolute_path(path_link);

                fb = dcache_get_filebox(tree, temp2, hint);
                sdsfree(path_link);
                free(temp2);
                goto out;
            }
        }
    }

    fbox_path = vfs_metadata_path(path, codename);
    fb = filebox_from_file(fbox_path);
    sdsfree(fbox_path);
out:
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
        slog(0, SLOG_ERROR, "dentry ref count is negative (%d)", dentry->count);
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
