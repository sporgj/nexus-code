#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "third/hashmap.h"
#include "third/queue.h"
#include "third/slog.h"

#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_uspace.h"
#include "uc_utils.h"

#define MAP_INIT_SIZE 2 << 12

typedef atomic_int ref_t;

typedef struct {
    const struct uc_dentry * parent;
    sds name;
} dcache_key_t;

typedef struct dcache_item_t {
    struct uc_dentry * dentry;
    SLIST_ENTRY(dcache_item_t) next_dptr;
} dcache_item_t;

struct uc_dentry {
    bool valid; /* if the entry is valid */
    ref_t count; /* number of references to the dentry */
    shadow_t dirnode_fname; /* the dirnode file name */
    dcache_key_t key;
    SLIST_HEAD(dcache_list_t, dcache_item_t) children;

    uv_mutex_t v_lock; /* required to change valid */
    uv_mutex_t c_lock; /* to change the children */
};

static Hashmap * dcache_hashmap = NULL;
static uv_mutex_t hashmap_lock;

static struct uc_dentry * root_dentry = NULL;
static uv_mutex_t dcache_lock;

unsigned long
crc32(const unsigned char * s, unsigned int len);

void
dcache_add(struct uc_dentry * dentry, struct uc_dentry * parent);

struct uc_dentry *
dcache_new(const char * name,
           const shadow_t * dirnode_name,
           const struct uc_dentry * parent);

/* for statistics */
uint64_t stats_total_cache_entries = 0;
uint64_t stats_cache_hits = 0;
uint64_t stats_cache_misses = 0;
uint64_t stats_cache_lookups = 0;

uv_timer_t stats_timer;
uv_thread_t stats_thread;

/*
 * Hashing function for a string
 * https://github.com/petewarden/c_hashmap/blob/master/hashmap.c
 */
int
hash_dentry(void * p_dcache_key)
{
    sds keystring = ((dcache_key_t *)p_dcache_key)->name;

    unsigned long key = crc32((unsigned char *)(keystring), strlen(keystring));

    /* Robert Jenkins' 32 bit Mix Function */
    key += (key << 12);
    key ^= (key >> 22);
    key += (key << 4);
    key ^= (key >> 9);
    key += (key << 10);
    key ^= (key >> 2);
    key += (key << 7);
    key ^= (key >> 12);

    /* Knuth's Multiplicative Method */
    return (key >> 3) * 2654435761;
}

bool
hash_is_equals(void * keyA, void * keyB)
{
    dcache_key_t *da = (dcache_key_t *)keyA, *db = (dcache_key_t *)keyB;
    return da->parent == db->parent && strcmp(da->name, db->name) == 0;
}

void print_dcache_stats(uv_timer_t * handle)
{
    printf("\n------------------ DCACHE STATS -------------------");
    printf("\n references: %lu, misses: %lu, hits: %lu", stats_cache_lookups,
           stats_cache_misses, stats_cache_hits);
    printf("\n---------------------------------------------------\n");
}


static void start_stats_thread()
{
    uv_loop_t * loop = uv_loop_new();
    uv_loop_init(loop);
    uv_timer_init(loop, &stats_timer);
    uv_timer_start(&stats_timer, print_dcache_stats, 5000, 10000);
    uv_run(loop, UV_RUN_DEFAULT);
}

void
dcache_init()
{
    if (dcache_hashmap) {
        return;
    }

    dcache_hashmap = hashmapCreate(MAP_INIT_SIZE, hash_dentry, hash_is_equals);
    uv_mutex_init(&hashmap_lock);
    uv_mutex_init(&dcache_lock);

    /* create our default dentry */
    root_dentry = dcache_new("", &uc_root_dirnode_shadow_name, NULL);
    dcache_add(root_dentry, NULL);

    uv_thread_create(&stats_thread, start_stats_thread, NULL);
}

struct uc_dentry *
dcache_new(const char * name,
           const shadow_t * dirnode_name,
           const struct uc_dentry * parent)
{
    struct uc_dentry * dentry;
    dentry = (struct uc_dentry *)calloc(1, sizeof(struct uc_dentry));
    if (dentry == NULL) {
        slog(0, SLOG_ERROR, "allocation error on new uc_dentry");
        return NULL;
    }

    memcpy(&dentry->dirnode_fname, dirnode_name, sizeof(shadow_t));
    dentry->key.parent = parent;
    dentry->key.name = sdsnew(name);
    dentry->valid = 1;
    uv_mutex_init(&dentry->v_lock);
    uv_mutex_init(&dentry->c_lock);

    /* initialize the list and return the pointer */
    SLIST_INIT(&dentry->children);

    return dentry;
}

// TODO
void
dcache_free(struct uc_dentry * dentry)
{
    dcache_item_t * ptr_entry;

    /* deallocate the children */
    uv_mutex_lock(&dentry->c_lock);
    while (!SLIST_EMPTY(&dentry->children)) {
        /* get the head, remove its children and then remove it */
        ptr_entry = SLIST_FIRST(&dentry->children);

        /* TODO dcache_free(dentry); */
        free(ptr_entry);

        SLIST_REMOVE_HEAD(&dentry->children, next_dptr);
    }
    uv_mutex_unlock(&dentry->c_lock);

    memset(dentry, 0, sizeof(struct uc_dentry));

    // TODO free from hashmap
}

void
dcache_add(struct uc_dentry * dentry, struct uc_dentry * parent)
{
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
    // this is probably an overkill as 
    hashmapPut(dcache_hashmap, &dentry->key, dentry);

    uv_mutex_lock(&hashmap_lock);
    stats_total_cache_entries++;
    uv_mutex_unlock(&hashmap_lock);
}

struct uc_dentry *
hash_lookup(struct uc_dentry * parent, const char * name)
{
    dcache_key_t v = {.parent = parent, .name = (const sds) name };

    struct uc_dentry * dentry
        = (struct uc_dentry *)hashmapGet(dcache_hashmap, &v);

    stats_cache_lookups++;
    if (dentry && dentry->valid) {
        stats_cache_hits++;
        return dentry;
    }

    stats_cache_misses++;
    return NULL;
}

static struct uc_dentry *
traverse(struct uc_dentry * parent_dentry,
         uc_dirnode_t ** p_dn,
         char * nch,
         char ** pch,
         sds * p_path_str)
{
    struct uc_dentry * dentry = parent_dentry;
    sds path_str = *p_path_str, dnode_path;
    ucafs_entry_type atype;
    char * metaname_str;
    int first = -1;
    const link_info_t * link_info;
    const shadow_t * shadow_name;
    uc_dirnode_t * dn = *p_dn, * alias_dn;

    while (nch) {
        link_info = NULL;
        first++;
        if (first) {
            path_str = sdscat(path_str, "/");
        }

        /* first find it in the dcache children */
        path_str = sdscat(path_str, nch);
        if ((dentry = hash_lookup(parent_dentry, nch))) {
            /* let's jump to the next one */
            shadow_name = &dentry->dirnode_fname;
            goto next;
        }

        /* otherwise, we need to add the entry to the dcache */
        shadow_name = dirnode_traverse(dn, nch, UC_ANY, &atype, &link_info);
        if (shadow_name == NULL || atype == UC_FILE) {
            break;
        }

        if (atype == UC_LINK) {
            // time for some fun
        }

next:
        /* next, lets load the entry */
        if ((metaname_str = metaname_bin2str(shadow_name)) == NULL) {
            break;
        }

        /* get the path to the dnode */
        dnode_path = uc_get_dnode_path(metaname_str);
        free(metaname_str);

        alias_dn = dn;
        dn = dirnode_from_file(dnode_path);
        sdsfree(dnode_path);
        if (dn == NULL) {
            break;
        }

        /* lets add the entry to the dirnode */
        if ((dentry = dcache_new(nch, shadow_name, parent_dentry)) == NULL) {
            break;
        }

        dcache_add(dentry, parent_dentry);
        parent_dentry = dentry;
        *p_dn = dn;
        dirnode_free(alias_dn);

        nch = strtok_r(NULL, "/", pch);
    }

    *p_path_str = path_str;

    /* now return the entry */
    if (nch == NULL) {
        return dentry;
    }

    if (dn) {
        dirnode_free(dn);
    }

    *p_dn = NULL;
    return NULL;
}

static struct uc_dentry *
real_lookup(const char * rel_path, uc_dirnode_t ** dn)
{
    /* first, lets get the parent dnode */
    struct uc_dentry * result_dentry;
    sds path_str = sdsnewlen("", strlen(rel_path));

    /* initalize the traversal */
    char *c_rel_path = strdup(rel_path), *nch, *pch;
    nch = strtok_r(c_rel_path, "/", &pch);

    result_dentry = traverse(root_dentry, dn, nch, &pch, &path_str);

    free(c_rel_path);
    sdsfree(path_str);

    return result_dentry;
}

/**
 * Performs a lookup of the corresponding path
 * @param path is the full file path
 * @param dirpath just the parent or the child directory
 * return the corresponding uc_dentry, else NULL if not found
 */
uc_dirnode_t *
dcache_lookup(const char * path, bool dirpath)
{
    struct uc_dentry * dentry = NULL;
    uc_dirnode_t * dirnode = dirnode_default_dnode();
    char * temp;
    sds temp_path, relpath;

    if ((relpath = uc_derive_relpath(path, dirpath)) == NULL) {
        slog(0, SLOG_ERROR, "getting relpath `%s` FAILED", path);
        return NULL;
    }

    // just return the root dirnode
    if (strlen(relpath)) {
        dentry = real_lookup(relpath, &dirnode);
    } else {
        dentry = root_dentry;
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
dcache_get_filebox(const char * path)
{
    const shadow_t * codename;
    char *fname = NULL, *temp = NULL, *temp2 = NULL;
    sds path_link = NULL, fbox_path = NULL;
    ucafs_entry_type atype;
    const link_info_t * link_info = NULL;
    uc_filebox_t * fb = NULL;
    uc_dirnode_t * dirnode = dcache_lookup(path, false);

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

    temp = metaname_bin2str(codename);
    fbox_path = uc_get_dnode_path(temp);

    fb = filebox_from_file(fbox_path);

    free(temp);
    sdsfree(fbox_path);
out:
    dirnode_free(dirnode);
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

    // THIS may be overwrought
    dirnode_clear_dentry(dn);
    dirnode_free(dn);
}

/**
 * Keep in mind, this doesn't remove the dirnode.
 */
void
dcache_rm(uc_dirnode_t * dn)
{
    struct uc_dentry * dentry = (struct uc_dentry *)dirnode_get_dentry(dn);

    uv_mutex_lock(&dentry->v_lock);
    dentry->valid = 0;
    uv_mutex_unlock(&dentry->v_lock);
}

static unsigned long crc32_tab[]
    = { 0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
        0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
        0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
        0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
        0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
        0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
        0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
        0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
        0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
        0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
        0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
        0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
        0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
        0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
        0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
        0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
        0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
        0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
        0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
        0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
        0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
        0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
        0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
        0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
        0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
        0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
        0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
        0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
        0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
        0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
        0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
        0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
        0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
        0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
        0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
        0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
        0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
        0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
        0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
        0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
        0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
        0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
        0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
        0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
        0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
        0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
        0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
        0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
        0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
        0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
        0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
        0x2d02ef8dL };

/* Return a 32-bit CRC of the contents of the buffer. */
unsigned long
crc32(const unsigned char * s, unsigned int len)
{
    unsigned int i;
    unsigned long crc32val;

    crc32val = 0;
    for (i = 0; i < len; i++) {
        crc32val = crc32_tab[(crc32val ^ s[i]) & 0xff] ^ (crc32val >> 8);
    }
    return crc32val;
}
