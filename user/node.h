#include "dnode.pb.h"
#include "sds.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dirnode {
    dnode_header_t header;
    dnode * proto;
    sds dnode_path;
};

class dnode;

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

/**
 * Flushes the dirnode to disk
 * @param dn
 * @return false if the dirnode does not have an associated path or if
 * dn_write returns false;
 */
bool dn_flush(struct dirnode * dn);

const encoded_fname_t * dn_add(struct dirnode * dn, ucafs_entry_type type);
const encoded_fname_t * dn_add_alias(struct dirnode * dn, ucafs_entry_type type,
    const encoded_fname_t * p_encoded_name);

#ifdef __cplusplus
}
#endif
