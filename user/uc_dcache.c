#include <stdlib.h>
#include <string.h>

#include "third/hashmap.h"
#include "third/slog.h"

#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_uspace.h"
#include "uc_utils.h"

static map_t dcache_table = NULL;

typedef struct {
    sds fpath;
} dirent_t;

void
dcache_init()
{
    if (dcache_table == NULL) {
        dcache_table = hashmap_new();
    }
}

// TODO find a C library for the map
static dirent_t *
lookup_cache(const sds dirpath)
{
    dirent_t * dirent;
    int err = hashmap_get(dcache_table, dirpath, (void **)&dirent);

    return err == MAP_OK ? dirent : NULL;
}

/**
 * Inserts a new mapping into the dcache
 */
static void
insert_into_dcache(const sds dirpath, uc_dirnode_t * dn)
{
    dirent_t * dirent = malloc(sizeof(dirent_t));
    dirent->fpath = sdsdup(dirnode_get_fpath(dn));
    hashmap_put(dcache_table, dirpath, dirent);
}

static uc_dirnode_t *
dcache_resolve(dirent_t * dirent)
{
    // TODO increase reference count
    return dirnode_from_file(dirent->fpath);
}

void
dcache_put(uc_dirnode_t * dn)
{
    dirnode_free(dn);
}

void
dcache_rm(const char * dirpath)
{
    int err;
    dirent_t * dirent;
    // removes the directory
    sds relative_path = uc_get_relative_path(dirpath);

    /* TODO update the call for removal to involve returning the element */
    err = hashmap_get(dcache_table, relative_path, (void **)&dirent);
    if (err == MAP_OK) {
        sdsfree(dirent->fpath);
        free(dirent);
        hashmap_remove(dcache_table, relative_path);
    }

    sdsfree(relative_path);
}

static uc_dirnode_t *
dcache_traverse(const sds relative_dirpath)
{
    char * encoded_name_str = NULL;
    char *pch, *nch, *c_rel_path, *new_path;
    sds dnode_path = NULL;
    const encoded_fname_t * encoded_fname;
    bool found = false;
    ucafs_entry_type atype;
    const link_info_t * link_info;
    uintptr_t ptr_val;
    sds branch_path = NULL;

    // TODO check for null
    uc_dirnode_t * dn = dirnode_default_dnode();

    c_rel_path = strdup(relative_dirpath);

    nch = strtok_r(c_rel_path, "/", &pch);
    while (nch) {
        link_info = NULL;
        /* find the entry in the dirnode */
        encoded_fname = dirnode_traverse(dn, nch, UC_ANY, &atype, &link_info);
        if (encoded_fname == NULL) {
            break;
        }

        if (link_info) {
            if (link_info->type == UC_HARDLINK) {
                slog(0, SLOG_ERROR, "can't traverse on hardlinks");
                break;
            } else {
                /* we have to jump to a different dirnode here */
                // form the link path
                branch_path = sdsnewlen(relative_dirpath, (pch - c_rel_path));
                branch_path = sdscat(branch_path, "/");
                branch_path = sdscat(branch_path, link_info->target_link);
                branch_path = sdscat(branch_path, pch);

                // resolve the path
                new_path = do_absolute_path(branch_path);

                // TODO LEAK HERE
                // call traverse with the new path
                return dcache_traverse(new_path);
                
                slog(0, SLOG_ERROR, "softlink traversal not supported yet");
                break;
            }
        }

        if ((encoded_name_str = encode_bin2str(encoded_fname)) == NULL) {
            break;
        }

        // get the path to the dnode
        dnode_path = uc_get_dnode_path(encoded_name_str);
        free(encoded_name_str);

        /* open the dnode for that path */
        dirnode_free(dn);
        dn = dirnode_from_file(dnode_path);

        sdsfree(dnode_path);
        dnode_path = NULL;

        if (dn == NULL) {
            break;
        }

        nch = strtok_r(NULL, "/", &pch);
    }

    found = (nch == NULL);

    if (!found) {
        if (dn) {
            dirnode_free(dn);
        }
    }

    if (dnode_path) {
        sdsfree(dnode_path);
        dnode_path = NULL;
    }

    free(c_rel_path);
    return dn;
}

/**
 * searches the content in the cache. if not found, it performs
 * a traversal and caches the content
 * @param path is the path to the file
 */
uc_dirnode_t *
__dcache_path(const char * path, bool get_parent_path)
{
    uc_dirnode_t * dnode;

    /* get the relative path */
    sds relative_path = get_parent_path ? uc_get_relative_parentpath(path)
                                        : uc_get_relative_path(path);
    if (relative_path == NULL) {
        return NULL;
    }

    /* lookup in the dnode_cache to find the entry */
    dirent_t * dirent = NULL; //lookup_cache(relative_path);
    if (dirent) {
        dnode = dcache_resolve(dirent);
        // only free when we're not adding the entry to the dcache
        sdsfree(relative_path);
    } else {
        dnode = dcache_traverse(relative_path);
        /* now add entry to the cache */
        insert_into_dcache(relative_path, dnode);
    }

    return dnode;
}

uc_dirnode_t *
dcache_get(const char * path)
{
    return __dcache_path(path, true);
}

uc_dirnode_t *
dcache_get_dir(const char * path)
{
    return __dcache_path(path, false);
}

uc_filebox_t *
dcache_get_filebox(const char * path)
{
    const encoded_fname_t * codename;
    char *fname = NULL, *temp = NULL, *temp2 = NULL; 
    sds path_link = NULL, fbox_path = NULL;
    uc_filebox_t * fb = NULL;
    uc_dirnode_t * dirnode = dcache_get(path);
    ucafs_entry_type atype;
    const link_info_t * link_info = NULL;

    if (dirnode == NULL) {
        return NULL;
    }

    if ((fname = do_get_fname(path)) == NULL) {
        dirnode_free(dirnode);
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
                fb = dcache_get_filebox(link_info->target_link);
                goto out;
            } else {
                // have an relative path
                path_link = do_get_dir(path);
                path_link = sdscat(path_link, "/");
                path_link = sdscat(path_link, link_info->target_link);
                temp2 = do_absolute_path(path_link);

                fb = dcache_get_filebox(temp2);
                sdsfree(path_link);
                free(temp2);
                goto out;
            }
        }
    }

    temp = encode_bin2str(codename);
    fbox_path = uc_get_dnode_path(temp);

    fb = filebox_from_file(fbox_path);

    free(temp);
    sdsfree(fbox_path);
out:
    dirnode_free(dirnode);
    sdsfree(fname);
    return fb;
}
