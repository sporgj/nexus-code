#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "third/sds.h"

#include "uc_types.h"
#include "uc_uspace.h"

struct dirnode;
typedef struct dirnode uc_dirnode_t;

struct uc_dentry;
struct metadata_entry;

typedef struct dirnode {
    dirnode_header_t header;
    dnode_list_head_t dirbox;
    acl_list_head_t lockbox;
    bucket_list_head_t buckets;

    bool is_root, bucket_update;
    sds dnode_path, cond_dirpath_is_root;
    dirnode_bucket_entry_t * bucket0;
    struct metadata_entry * mcache;
} uc_dirnode_t;

uc_dirnode_t *
dirnode_new();

uc_dirnode_t *
dirnode_new2(const shadow_t * id, const uc_dirnode_t * parent);

static inline sds
dirnode_get_dirpath(const uc_dirnode_t * dn, bool include_slash)
{
    if (dn->is_root) {
        return sdsdup(dn->cond_dirpath_is_root);
    }

    return sdscat(sdsdup(dn->dnode_path), (include_slash ? "_/" : "_"));
}

static inline void
dirnode_set_filepath(uc_dirnode_t * dirnode, const char * path)
{
    if (dirnode->dnode_path) {
        sdsfree(dirnode->dnode_path);
    }

    dirnode->dnode_path = sdsnew(path);
}

static inline sds
dirnode_get_path(const uc_dirnode_t * dirnode)
{
    return dirnode->dnode_path ? sdsdup(dirnode->dnode_path) : NULL;
}

void
dirnode_rm_from_journal(uc_dirnode_t * dirnode, const shadow_t * shdw);

/**
 * Returns if the dirnode has any entries that need to be garbage collected
 * @param dirnode
 * @return true if any
 */
bool
dirnode_has_garbage(uc_dirnode_t * dirnode);

const shadow_t *
dirnode_peek_garbage(uc_dirnode_t * dirnode);

/**
 * Generates a new dirnode object with a pregenerated name
 * @param id is the ID of the dirnode, NULL if you want the ID randomly
 * generated
 */
uc_dirnode_t *
dirnode_new_alias(const shadow_t * id);

uc_dirnode_t *
dirnode_new_root(const shadow_t * id);

void
dirnode_set_root(uc_dirnode_t * dirnode, shadow_t * root_dnode);

void
dirnode_set_parent(uc_dirnode_t * dn, const uc_dirnode_t * parent);

const shadow_t *
dirnode_get_parent(uc_dirnode_t * dn);

struct metadata_entry *
dirnode_get_metadata(uc_dirnode_t * dn);

void
dirnode_set_metadata(uc_dirnode_t *, struct metadata_entry *);

/**
 * Creates a new dirnode object from the path.
 * @param filepath is the absolute path to the file
 * return NULL if path not found
 */
uc_dirnode_t *
dirnode_from_file(const sds file_path);

void
dirnode_free(uc_dirnode_t * dirnode);

/**
 * Writes the dnode to disk
 * @param dn
 * @param fpath
 * @return true if everything went fine
 */
bool
dirnode_write(uc_dirnode_t * dn, const char * fpath);

bool
dirnode_equals(uc_dirnode_t * dn1, uc_dirnode_t * dn2);

/**
 * Flushes the dirnode to disk
 * @param dn
 * @return false if the dirnode does not have an associated path or if
 * dirnode_write returns false;
 */
bool
dirnode_flush(uc_dirnode_t * dn);

bool
dirnode_fsync(uc_dirnode_t * dn);

/**
 * Used to add files and directories
 * @see dinode_add_alias. Sets p_encoded_name and link_info to NULL
 */
shadow_t *
dirnode_add(uc_dirnode_t * dn,
            const char * fname,
            ucafs_entry_type type,
            int journal);

shadow_t *
dirnode_add_link(uc_dirnode_t * dn,
                 const char * fname,
                 const link_info_t * link_info);

/**
 * Adding an entry to the dirnode
 * @param dn is the dirnode object
 * @param fname is the file name
 * @param type is the entry type
 * @param jrnl if the entry we are adding has no on-disk entry
 * @param p_encoded_name if the encoded name has been precomputed
 * @param link_info
 * @return the encoded name. Keep in mind if a p_encoded_name is passed, the
 * variable returned would be of a different address and hence requires a
 * separate deallocation.
 */
shadow_t *
dirnode_add_alias(uc_dirnode_t * dn,
                  const char * fname,
                  ucafs_entry_type type,
                  int jrnl,
                  const shadow_t * p_encoded_name,
                  const link_info_t * p_link_info);

shadow_t *
dirnode_rm(uc_dirnode_t * dn,
           const char * realname,
           ucafs_entry_type type,
           ucafs_entry_type * p_type,
           int * jrnl,
           link_info_t ** pp_link_info);

const char *
dirnode_enc2raw(uc_dirnode_t * dn,
                const shadow_t * encoded_name,
                ucafs_entry_type type,
                ucafs_entry_type * p_type);

const shadow_t *
dirnode_raw2enc(uc_dirnode_t * dn,
                const char * realname,
                ucafs_entry_type type,
                ucafs_entry_type * p_type);

const shadow_t *
dirnode_traverse(uc_dirnode_t * dn,
                 const char * realname,
                 ucafs_entry_type type,
                 ucafs_entry_type * p_type,
                 int * p_journal,
                 const link_info_t ** pp_link_info);

int
dirnode_rename(uc_dirnode_t * dn,
               const char * oldname,
               const char * newname,
               ucafs_entry_type type,
               ucafs_entry_type * p_type,
               shadow_t ** pp_shadow1_bin,
               shadow_t ** pp_shadow2_bin,
               link_info_t ** pp_link_info1,
               link_info_t ** pp_link_info2,
               int * jrnl1,
               int * jrnl2);

int
dirnode_checkacl(uc_dirnode_t * dn, acl_rights_t rights);

void
dirnode_lockbox_clear(uc_dirnode_t * dn);

int
dirnode_lockbox_add(uc_dirnode_t * dn, const char * name, acl_rights_t rights);

// internal functions to manage the dirnode in-memory object
void
dirnode_mark_dirty(uc_dirnode_t * dn);
void
dirnode_mark_clean(uc_dirnode_t * dn);
bool
dirnode_is_dirty(uc_dirnode_t * dn);
int
dirnode_trylock(uc_dirnode_t * dn);
void
dirnode_unlock(uc_dirnode_t * dn);

/** returns the root's shadow name */
const shadow_t *
dirnode_get_root(uc_dirnode_t * dirnode);

#ifdef __cplusplus
}
#endif
