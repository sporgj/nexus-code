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
#include "third/log.h"

#include <sys/stat.h>
#include <unistd.h>

#include <string.h>

#include <uv.h>

struct dirty_item;

static Hashmap * metadata_hashmap;

static metadata_entry_t *
_create_entry(uc_dirnode_t * dn, const shadow_t * shdw)
{
    int ret = -1, *hash;
    void * ptr;
    metadata_entry_t * entry
        = (metadata_entry_t *)calloc(1, sizeof(metadata_entry_t));
    if (entry == NULL) {
        log_fatal("allocation failed for metadata_entry_t");
        return NULL;
    }

    entry->dn = dn;
    entry->epoch = time(NULL);
    memcpy(&entry->shdw_name, shdw, sizeof(shadow_t));
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
        entry = NULL;
    }

    return entry;
}

void
metadata_update_entry(struct metadata_entry * entry)
{
    entry->epoch = time(NULL);
}

static inline void
_update_entry(struct metadata_entry * entry, uc_dirnode_t * dn)
{
    if (entry->dn) {
        dirnode_free(entry->dn);
    }

    entry->dn = dn;
}

static inline void
_free_entry(metadata_entry_t * entry)
{
    if (entry->dn) {
        dirnode_free(entry->dn);
    }

    entry->dn = NULL;

    free(entry);
}

void
metadata_rm_dirnode(const shadow_t * shdw)
{
    metadata_entry_t * entry;

    /* check if the item is in the cache */
    entry = (metadata_entry_t *)hashmapRemove(metadata_hashmap, (void *)shdw);
    if (entry == NULL) {
        return;
    }

    dirnode_free(entry->dn);
    free(entry);
}

/**
 * Checks for journal section of the parent dirnode to create on-disk file
 * @param parent_dentry
 * @param fpath is the path to the new dirnode
 * @param p_dirnode would be the destination pointer for the new dirnode
 * @return 0 on success
 */
static int
_metadata_on_demand(struct uc_dentry * parent_dentry,
                    const shadow_t * shdw,
                    const char * fpath,
                    uc_dirnode_t ** p_dirnode)
{
    int err = -1, ret = -1;
    uc_dirnode_t *dn = NULL, *parent_dirnode = parent_dentry->metadata->dn;
    *p_dirnode = NULL;

    if (parent_dirnode == NULL) {
        // then we have to load it from the metadata
        // TODO include code here to call metadata_get_dirnode()
        // will need to implement dentry_path()
        log_fatal("parent_dirnode == NULL");
        goto out;
    }

    // then let's create a new dirnode and return
    if ((dn = dirnode_new2(shdw, parent_dirnode)) == NULL) {
        log_error("new dirnode failed: %s", fpath);
        goto out;
    }

    // XXX might be wiser to check if the file already exists on disk
    if (!dirnode_write(dn, fpath)) {
        log_error("writing '%s' dirnode FAILED", fpath);
        goto out;
    }

    /* now we can delete the entry from the journal.
     * XXX do we need to flush the dirnode immediately? */
    dirnode_rm_from_journal(parent_dirnode, shdw);
    if (!dirnode_flush(parent_dirnode)) {
        log_error("flushing parent dirnode failed\n");
        goto out;
    }

    /* lets not forget to set the path */
    dirnode_set_path(dn, fpath);
    *p_dirnode = dn;

    ret = 0;
out:
    if (ret && dn) {
        dirnode_free(dn);
    }

    return ret;
}

/**
 * Loads the dirnode associated with a particular shadow
 * @param parent_path is the path to the parent directory
 * @param dentry is the element's parent dentry
 * @param shdw is the shadow name to load
 */
uc_dirnode_t *
metadata_get_dirnode(const char * path,
                     struct uc_dentry * dentry)
{
    int err;
    bool in_journal;
    uc_dirnode_t * dn = NULL;
    metadata_entry_t * entry;
    struct stat st;
    int * hashval;
    sds fpath = NULL;
    struct uc_dentry * parent_dentry = (struct uc_dentry *)dentry->key.parent;
    const shadow_t * shdw = &dentry->shdw_name;

    /* check if the item is in the cache */
    entry = (metadata_entry_t *)hashmapGet(metadata_hashmap, (void *)shdw);
    if (entry == NULL) {
        goto load_from_disk;
    }

    /* if found, check the on-disk time */
    if ((fpath = dirnode_get_path(entry->dn)) == NULL) {
        log_error("dirnode_get_path returned NULL (%s)", fpath);
        goto out;
    }

    if (stat(fpath, &st)) {
        log_error("file '%s' does not exist", fpath);
        goto out;
    }

    if (difftime(st.st_mtime, entry->epoch) > 0) {
        /* frees the dirnode object and load it from disk */
        dirnode_free(entry->dn);
        entry->dn = NULL;
        goto load_from_disk;
    }

    /* we found the dirnode, and it's the latest version */
    dn = entry->dn;
    goto out;

load_from_disk:
    if (fpath == NULL && (fpath = vfs_afsx_path(path, shdw)) == NULL) {
        log_error("vfs_dirnode_path returned NULL (%s)", fpath);
        goto out;
    }

    /* this is the code for on-demand loading of the dirnode */
    if (parent_dentry && _metadata_on_demand(parent_dentry, shdw, fpath, &dn)) {
        log_error("creating metadata failed (%s)", path);
        goto out;
    }

    /* load it from disk */
    if ((dn = dirnode_from_file(fpath)) == NULL) {
        goto out;
    }

    // add it to the metadata cache
    if (entry == NULL) { 
        /* associate it to the dentry */
         entry = _create_entry(dn, shdw);
    } else {
        /* if entry already exists, just update it */
        _update_entry(entry, dn);
    }

    if (entry == NULL) {
        log_error("metadata entry could not be created");
        dirnode_free(dn);
        dn = NULL;
        goto out;
    }

    /* lets not forget to add it to the dentry */
    // TODO add to dentry to metadata's list
    dentry->metadata = entry;
    dentry->negative = false;
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
        log_fatal("hashmapCreate returns NULL");
        return -1;
    }

    return 0;
}

void
metadata_exit()
{
    // TODO clear all data here
}
