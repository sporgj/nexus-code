#pragma once

#if 0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "nexus.h"
#include "nexus_log.h"
#include "nexus_backend.h"
#include "nexus_metadata_store.h"



#define NEXUS_FILENAME_PREFIX "f"
#define NEXUS_PREFIX_SIZE(x) (sizeof(x) - 1)

struct uuid *
filename_str2bin(const char * str);

char *
filename_bin2str(const struct uuid * bin);
#endif
