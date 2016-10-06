#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "third/sds.h"

#include "uc_types.h"
#include "uc_uspace.h"

struct dirnode;
typedef struct dirnode uc_dirnode_t;

uc_dirnode_t *
dirnode_new();

uc_dirnode_t *
dirnode_default_dnode();

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

const encoded_fname_t *
dirnode_add(uc_dirnode_t * dn, sds fname, ucafs_entry_type type);

const encoded_fname_t *
dirnode_add_alias(uc_dirnode_t * dn,
                  sds fname,
                  ucafs_entry_type type,
                  const encoded_fname_t * p_encoded_name);

const encoded_fname_t *
dirnode_rm(uc_dirnode_t * dn, const sds realname, ucafs_entry_type type);

const char *
dirnode_enc2raw(const uc_dirnode_t * dn,
                const encoded_fname_t * encoded_name,
                ucafs_entry_type type);

const encoded_fname_t *
dirnode_raw2enc(const uc_dirnode_t * dn,
                const char * realname,
                ucafs_entry_type type);

const encoded_fname_t *
dirnode_rename(uc_dirnode_t * dn,
               const sds oldname,
               const sds newname,
               ucafs_entry_type type);

#ifdef __cplusplus
}
#endif
