#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "third/hashmap.h"
#include "third/log.h"
#include "third/queue.h"
#include "third/log.h"

#include "uc_vfs.h"
#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_filebox.h"
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
dcache_traverse(struct uc_dentry * root_dentry,
                struct uc_dentry * parent_dentry,
                sds root_path,
                const char * canonical_path,
                char * path_cstr,
                sds * final_path)
{
    struct uc_dentry * dentry = parent_dentry;
    ucafs_entry_type atype;
    char *metaname_str, *nch, *pch;
    const link_info_t * link_info;
    const shadow_t * shadow_name;
    uc_dirnode_t *dn = NULL, *dn2;

    /* the string builder */
    sds curr_path = sdsdup(root_path);

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

        /* 1 - hash_lookup: checks if the entry was already created */
        if ((dentry = hash_lookup(parent_dentry, nch))) {
            /* let's jump to the next one */
            goto next1;
        }

        /* 2 - Fetch the parent dirnode from disk */
        if ((dn = metadata_get_dirnode(curr_path, parent_dentry)) == NULL) {
            break;
        }

        /* 3 - load the shadow name of the new dentry */
        shadow_name = dirnode_traverse(dn, nch, UC_ANY, &atype, &link_info);
        if (shadow_name == NULL || atype == UC_FILE) {
            break;
        }

        /* special care for our symlinks :( */
        if (atype == UC_LINK) {
            /* get the link and recursively traverse */
            sds temp_path = NULL;
            char * link_cstr = strdup(link_info->target_link);
            dentry = dcache_traverse(root_dentry, parent_dentry, curr_path,
                                     canonical_path, link_cstr, &temp_path);
            sdsfree(curr_path);
            free(link_cstr);

            /* make the curr path point to the new temp_path */
            curr_path = temp_path;

            if (dentry) {
                goto next1;
            }
        }

        /* 4 - now create the new entry */
        dentry = dcache_new(nch, shadow_name, parent_dentry,
                            parent_dentry->dentry_tree);
        if (dentry == NULL) {
            log_error("dcache_new returned NULL");
            break;
        }

        dcache_add(dentry, parent_dentry);

    next1:
        /* move the path to the next component */
        // FIXME potential issues with .. and .
        curr_path = sdscat(curr_path, "/");
        curr_path = sdscat(curr_path, nch);

        parent_dentry = dentry;
        nch = strtok_r(NULL, "/", &pch);
    }

    /* now return the entry */
    /* if it's not null, it means we haven't parsed to the end of the string */
    if (nch) {
        *final_path = NULL;
        sdsfree(curr_path);
        return NULL;
    }

    *final_path = curr_path;

    return dentry;
}

static struct uc_dentry *
real_lookup(struct uc_dentry * root_dentry,
            sds root_path,
            const char * canonical_path,
            const char * rel_path,
            uc_dirnode_t ** pp_dirnode)
{
    struct uc_dentry * dentry;
    sds curr_path = NULL;
    char * path_cstr = strdup(rel_path);

    dentry = dcache_traverse(root_dentry, root_dentry, root_path,
                             canonical_path, path_cstr, &curr_path);

    /* dentry points to the entry we're interested in. Now, we have to load its
     * associated dirnode */
    if (dentry) {
        *pp_dirnode = metadata_get_dirnode(curr_path, dentry);
        sdsfree(curr_path);
    }

    free(path_cstr);
    return dentry;
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
    sds relpath;

    if ((relpath = vfs_relpath(path, dirpath)) == NULL) {
        log_warn("getting relpath `%s` FAILED", path);
        return NULL;
    }

    // just return the root dirnode
    if (strlen(relpath)) {
        dentry = real_lookup(dentry, tree->root_path, path, relpath, &dirnode);
    } else {
        dirnode = metadata_get_dirnode(path, dentry);
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
    int err;
    bool in_journal;
    journal_op_t jrnl_op;
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

                fb = dcache_get_filebox(tree, path_link, hint);
                sdsfree(path_link);
                goto out;
            }
        }
    }

    fbox_path = vfs_metadata_path(path, codename);

    /* check if the file is on disk */
    err = dirnode_search_journal(dirnode, codename, &jrnl_op);
    in_journal = (err == 0 && jrnl_op == CREATE_FILE);
    if (!in_journal) {
        goto load_from_disk;
    }

    /* then we have to create the filebox */
    if ((fb = filebox_new2(codename, dirnode)) == NULL) {
        log_error("filebox_new2 failed");
        goto cleanup;
    }

    if (!filebox_write(fb, fbox_path)) {
        log_error("filebox_write (%s) FAILED", fbox_path);
        goto cleanup;
    }

    /* delete the entry from the dirnode
     * XXX should we flush it now or later ? */
    dirnode_rm_from_journal(dirnode, codename);
    if (!dirnode_flush(dirnode)) {
        log_error("dirnode_flush (%s) FAILED", path);
        goto cleanup;
    }

    /* set the path to allow flushing the filebox */
    filebox_set_path(fb, fbox_path);
    goto out;

load_from_disk:
    fb = filebox_from_file2(fbox_path, hint);
    goto out;

cleanup:
    if (fb) {
        filebox_free(fb);
        fb = NULL;
    }

out:
    sdsfree(fbox_path);

    if (link_info) {
        free((link_info_t *)link_info);
    }

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
