#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "uc_uspace.h"
#include "sds.h"
#include "types.h"

struct dirnode;

struct dirnode * dn_new();

struct dirnode * dn_default_dnode();

/**
 * Creates a new dirnode object from the path.
 * @param filepath is the absolute path to the file
 * return NULL if path not found
 */
struct dirnode * dn_from_file(const sds file_path);

/**
 * Writes the dnode to disk
 * @param dn
 * @param fpath
 * @return true if everything went fine
 */
bool dn_write(struct dirnode * dn, const char * fpath);

bool dn_equals(struct dirnode * dn1, struct dirnode * dn2);

/**
 * Flushes the dirnode to disk
 * @param dn
 * @return false if the dirnode does not have an associated path or if
 * dn_write returns false;
 */
bool dn_flush(struct dirnode * dn);

const encoded_fname_t * dn_add(
    struct dirnode * dn, sds fname, ucafs_entry_type type);
const encoded_fname_t * dn_add_alias(struct dirnode * dn, sds fname,
    ucafs_entry_type type, const encoded_fname_t * p_encoded_name);

const encoded_fname_t * dn_rm(
    struct dirnode * dn, const sds realname, ucafs_entry_type type);

const char * dn_enc2raw(const struct dirnode * dn,
    const encoded_fname_t * encoded_name, ucafs_entry_type type);

const encoded_fname_t * dn_raw2enc(
    const struct dirnode * dn, const char * realname, ucafs_entry_type type);

const encoded_fname_t * dn_rename(struct dirnode * dn, const sds oldname,
    const sds newname, ucafs_entry_type type);

#ifdef __cplusplus
}
#endif
