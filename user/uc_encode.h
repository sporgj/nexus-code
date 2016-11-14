#pragma once
#include "uc_types.h"

char *
metaname_bin2str(const shadow_t * bin);

shadow_t *
metaname_str2bin(const char * encoded_filename);

char *
filename_bin2str(const shadow_t * bin);

shadow_t *
filename_str2bin(const char * encoded_filename);
