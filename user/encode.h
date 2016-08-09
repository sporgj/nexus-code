#pragma once
#include "types.h"

/**
 * Returns a string representation of a code
 * @param is the code
 * @return malloced string on success else NULL
 */
char * encode_filename(const encoded_fname_t * code);

/**
 * Converts string version of a filename to code type
 * @param encoded_filename is the filename
 * @return malloced stirng on success
 */
encoded_fname_t * decode_filename(const char * encoded_filename);
