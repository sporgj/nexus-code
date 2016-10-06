#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "third/sds.h"

#include "uc_types.h"
#include "uc_uspace.h"

struct dirnode;

struct dirnode *
dirnode_new();

struct dirnode *
dirnode_default_dnode();

/**
 * Creates a new dirnode object from the path.
 * @param filepath is the absolute path to the file
 * return NULL if path not found
 */
struct dirnode *
dirnode_from_file(const sds file_path);

void
dirnode_free(struct dirnode * dirnode);

const sds
dirnode_get_fpath(struct dirnode * dirnode);

/**
 * Writes the dnode to disk
 * @param dn
 * @param fpath
 * @return true if everything went fine
 */
bool
dirnode_write(struct dirnode * dn, const char * fpath);

bool
dirnode_equals(struct dirnode * dn1, struct dirnode * dn2);

/**
 * Flushes the dirnode to disk
 * @param dn
 * @return false if the dirnode does not have an associated path or if
 * dirnode_write returns false;
 */
bool
dirnode_flush(struct dirnode * dn);

const encoded_fname_t *
dirnode_add(struct dirnode * dn, sds fname, ucafs_entry_type type);

const encoded_fname_t *
dirnode_add_alias(struct dirnode * dn,
                  sds fname,
                  ucafs_entry_type type,
                  const encoded_fname_t * p_encoded_name);

const encoded_fname_t *
dirnode_rm(struct dirnode * dn, const sds realname, ucafs_entry_type type);

const char *
dirnode_enc2raw(const struct dirnode * dn,
                const encoded_fname_t * encoded_name,
                ucafs_entry_type type);

const encoded_fname_t *
dirnode_raw2enc(const struct dirnode * dn,
                const char * realname,
                ucafs_entry_type type);

const encoded_fname_t *
dirnode_rename(struct dirnode * dn,
               const sds oldname,
               const sds newname,
               ucafs_entry_type type);

#ifdef __cplusplus
}
#endif
