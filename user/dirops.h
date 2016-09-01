#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates a new file at the corresponding file path
 * @param fpath is the file path
 * @param encoded_name_dest is the resulting encoded filename
 * the encoded file name (malloc), set to NULL if error
 * @return 0 on success
 */
int fops_new(char * fpath, char ** encoded_name_dest);
int dops_new(char * dpath, char ** encoded_name_dest);

/**
 * Returns the raw file name of an encoded path
 * @param encoded_name is the encoded file name
 * @param dir_path is the directory in which the file resides
 * @param raw_name_dest is the resulting the raw file name,
 * set to NULL if error (ex. file not be found)
 * @return 0 on success
 */
int fops_code2plain(char * encoded_name, char * dir_path, char ** raw_name_dest);
int dops_code2plain(char * encoded_name, char * dir_path, char ** raw_name_dest);

/**
 * Returns the encoded name from a file path. This is used by the LINUX
 * vfs to lookup decoded directory entries (it's the complementary to the
 * decode operation
 *
 * @param fpath_raw is the raw file path
 * @param encoded_fname_dest is the encoded file name destination
 * @return 0 on success
 */
int fops_plain2code(char * fpath_raw, char ** encoded_fname_dest);
int dops_plain2code(char * dpath_raw, char ** encoded_dname_dest);

/**
 * Removes a file from the respective file path
 * @param fpath_raw is the raw file name
 * @return 0 on success
 */
int fops_remove(char * fpath_raw, char ** encoded_fname_dest);
int dops_remove(char * fpath_raw, char ** encoded_fname_dest);

int fops_rename(char * old_plain_path, char * new_plain_path,
                char ** raw_name_dest);

#ifdef __cplusplus
}
#endif
