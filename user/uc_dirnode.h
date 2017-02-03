#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <uv.h>

#include "third/sds.h"

#include "uc_types.h"
#include "uc_uspace.h"

struct dirnode;
typedef struct dirnode uc_dirnode_t;

struct uc_dentry;
struct metadata_entry;

uc_dirnode_t *
dirnode_new();

uc_dirnode_t *
dirnode_new2(const shadow_t * id, const uc_dirnode_t * parent);

/**
 * Generates a new dirnode object with a pregenerated name
 * @param id is the ID of the dirnode, NULL if you want the ID randomly
 * generated
 */
uc_dirnode_t *
dirnode_new_alias(const shadow_t * id);

uc_dirnode_t *
dirnode_default_dnode();

void
dirnode_set_parent(uc_dirnode_t * dn, const uc_dirnode_t * parent);

const shadow_t *
dirnode_get_parent(uc_dirnode_t * dn);

void
dirnode_set_dentry(uc_dirnode_t * dirnode, const struct uc_dentry * dentry);

const struct uc_dentry *
dirnode_get_dentry(uc_dirnode_t * dirnode);

void
dirnode_clear_dentry(uc_dirnode_t * dirnode);

struct metadata_entry * dirnode_get_metadata(uc_dirnode_t * dn);
void dirnode_set_metadata(uc_dirnode_t *, struct metadata_entry *);

/**
 * Creates a new dirnode object from the path.
 * @param filepath is the absolute path to the file
 * return NULL if path not found
 */
uc_dirnode_t *
dirnode_from_file(const sds file_path);

void
dirnode_free(uc_dirnode_t * dirnode);

const sds
dirnode_get_fpath(uc_dirnode_t * dirnode);

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
dirnode_add(uc_dirnode_t * dn, const char * fname, ucafs_entry_type type);

shadow_t *
dirnode_add_link(uc_dirnode_t * dn,
                 const char * fname,
                 const link_info_t * link_info);

/**
 * Adding an entry to the dirnode
 * @param dn is the dirnode object
 * @param fname is the file name 
 * @param type is the entry type
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
                  const shadow_t * p_encoded_name,
                  const link_info_t * p_link_info);

shadow_t *
dirnode_rm(uc_dirnode_t * dn,
           const char * realname,
           ucafs_entry_type type,
           ucafs_entry_type * p_type,
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
                 const link_info_t ** pp_link_info);

int
dirnode_rename(uc_dirnode_t * dn,
               const char * oldname,
               const char * newname,
               ucafs_entry_type type,
               ucafs_entry_type *p_type,
               shadow_t ** pp_shadow1_bin,
               shadow_t ** pp_shadow2_bin,
               link_info_t ** pp_link_info1,
               link_info_t ** pp_link_info2);

int dirnode_setacl(uc_dirnode_t * dn, const char * aclstr);

// internal functions to manage the dirnode in-memory object
void dirnode_mark_dirty(uc_dirnode_t * dn);
void dirnode_mark_clean(uc_dirnode_t * dn);
bool dirnode_is_dirty(uc_dirnode_t * dn);
int dirnode_trylock(uc_dirnode_t * dn);
void dirnode_unlock(uc_dirnode_t * dn);

#ifdef __cplusplus
}
#endif
