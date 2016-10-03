#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

/**
 * Creates a new file at the corresponding file path
 * @param fpath is the file path
 * @param encoded_name_dest is the resulting encoded filename
 * the encoded file name (malloc), set to NULL if error
 * @return 0 on success
 */
int dirops_new(const char * fpath, ucafs_entry_type type,
               char ** encoded_name_dest);

/**
 * Returns the raw file name of an encoded path
 * @param encoded_name is the encoded file name
 * @param dir_path is the directory in which the file resides
 * @param raw_name_dest is the resulting the raw file name,
 * set to NULL if error (ex. file not be found)
 * @return 0 on success
 */
int dirops_code2plain(char * encoded_name, char * dir_path,
                      ucafs_entry_type type, char ** raw_name_dest);

/**
 * Returns the encoded name from a file path. This is used by the LINUX
 * vfs to lookup decoded directory entries (it's the complementary to the
 * decode operation
 *
 * @param fpath_raw is the raw file path
 * @param type dir/file
 * @param encoded_fname_dest is the encoded file name destination
 * @return 0 on success
 */
int dirops_plain2code(const char * fpath_raw, ucafs_entry_type type,
                    char ** encoded_fname_dest);

/**
 * Removes a file from the respective file path
 * @param fpath_raw is the raw file name
 * @return 0 on success
 */
int dirops_remove(const char * fpath_raw, ucafs_entry_type type,
                  char ** encoded_fname_dest);

int dirops_rename(const char * from_path, const char * to_path,
                  ucafs_entry_type type, char ** raw_name_dest);
#ifdef __cplusplus
}
#endif
