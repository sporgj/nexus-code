#pragma once
#include "uc_types.h"

char *
metaname_bin2str(const encoded_fname_t * bin);

encoded_fname_t *
metaname_str2bin(const char * encoded_filename);

char *
filename_bin2str(const encoded_fname_t * bin);

encoded_fname_t *
filename_str2bin(const char * encoded_filename);
