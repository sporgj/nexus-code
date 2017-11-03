/**
 * defines all the functions used by the untrusted code
 */
#include <stdlib.h>

#include "nexus.h"
#include "log.h"

#include "nx_types.h"

/* nx_utils.c */
void
generate_uuid(struct uuid * uuid);


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

// supernode

/**
 * Creates a new supernode & initializes the uuid.
 * @return NULL on fail
 */
struct supernode *
supernode_new();
