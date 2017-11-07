/**
 * defines all the functions used by the untrusted code
 */
#include <stdlib.h>

#include "nexus.h"
#include "nexus_log.h"

#include "nexus_types.h"
#include "nexus_util.h"

/* nx_encode.c */
char *
metaname_bin2str(const struct uuid * uuid);

struct uuid *
metaname_str2bin(const char * str);

char *
filename_bin2str(const struct uuid * uuid);

struct uuid *
filename_str2bin(const char * str);


/* nx_volume.h */
