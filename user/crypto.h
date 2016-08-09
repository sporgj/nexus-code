#pragma once
#include "dirnode.h"
#include "types.h"

/**
 * will initialize and seal crypto information in a filebox
 * @param fb is the filebox object
 * @return 0 on success
 */
int crypto_init_filebox(DirNode * fb);

/**
 * Adds a new file entry in the filebox
 * @param fb is the filebox
 * @param fname is the plain filename
 * @return the encoded file name
 */
encoded_fname_t * crypto_add_file(DirNode * fb, const char * fname);

/**
 * Returns the plain file name of a file
 * @param fb is the filebox object
 * @param codename is the encoded file name
 * @return the plain file name
 */
char * crypto_get_fname(DirNode * fb, const encoded_fname_t * codename);

/**
 * Returns the code object
 * @param fb
 * @param plain_filename
 * @return the code object
 */
encoded_fname_t * crypto_get_codename(DirNode * fb, const char * plain_filename);
