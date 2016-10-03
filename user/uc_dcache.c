#include <stdlib.h>
#include <string.h>

#include "encode.h"
#include "hashmap.h"
#include "uc_dnode.h"
#include "uc_uspace.h"

static map_t dcache_table = NULL;

typedef struct {
    const char * fpath;
} dirent_t;

void dcache_init()
{
    if (dcache_table == NULL) {
        dcache_table = hashmap_new();
    }
}

// TODO find a C library for the map
static dirent_t * lookup_cache(const sds dirpath)
{
    dirent_t * dirent;
    int err = hashmap_get(dcache_table, dirpath, (void **)&dirent);

    return err == MAP_OK ? dirent : NULL;
}

static struct dirnode * dcache_resolve(dirent_t * dirent)
{
    // TODO increase reference count
    sds dnode_path = uc_get_dnode_path(dirent->fpath);
    struct dirnode * dn = dn_from_file(dnode_path);
    sdsfree(dnode_path);

    return dn;
}

void dcache_put(struct dirnode * dn)
{
    free(dn);
}

static struct dirnode * dcache_traverse(const sds relative_dirpath)
{
    char * encoded_name_str = NULL;
    char *pch, *nch, *c_rel_path;
    sds dnode_path = NULL;
    const encoded_fname_t * encoded_fname;
    bool found = false;
    uintptr_t ptr_val;

    // TODO check for null
    struct dirnode * dn = dn_default_dnode();

    c_rel_path = strdup(relative_dirpath);

    nch = strtok_r(c_rel_path, "/", &pch);
    while (nch) {
        /* find the entry in the dirnode */
        if ((encoded_fname = dn_raw2enc(dn, nch, UCAFS_TYPE_DIR)) == NULL) {
            break;
        }

        if ((encoded_name_str = encode_bin2str(encoded_fname)) == NULL) {
            break;
        }

        // get the path to the dnode
        dnode_path = uc_get_dnode_path(encoded_name_str);
        free(encoded_name_str);

        /* open the dnode for that path */
        cfree(&dn);
        dn = dn_from_file(dnode_path);

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
            cfree(&dn);
        }

        if (dnode_path) {
            sdsfree(dnode_path);
            dnode_path = NULL;
        }
    }

    free(c_rel_path);
    return found ? dn : NULL;
}

/**
 * searches the content in the cache. if not found, it performs
 * a traversal and caches the content
 * @param path is the path to the file
 */
struct dirnode * __dcache_path(const char * path, bool get_parent_path)
{
    struct dirnode * dnode;

    /* get the relative path */
    sds relative_path = get_parent_path
        ? uc_get_relative_parentpath(path)
        : uc_get_relative_path(path);
    if (relative_path == NULL) {
        return NULL;
    }

    /* lookup in the dnode_cache to find the entry */
    dirent_t * dirent = lookup_cache(relative_path);
    dnode = (dirent == NULL) ? dcache_resolve(dirent)
                             : dcache_traverse(relative_path);

    sdsfree(relative_path);

    return dnode;
}

struct dirnode * dcache_get(const char * path)
{
    return __dcache_path(path, true);
}

struct dirnode * dcache_get_dir(const char * path)
{
    return __dcache_path(path, false);
}
