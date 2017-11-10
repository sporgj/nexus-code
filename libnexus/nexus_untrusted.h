/**
 * defines all the functions used by the untrusted code
 */
#include <stdlib.h>

#include <sgx_urts.h>

#include "nexus.h"
#include "nexus_log.h"

#include "nexus_types.h"
#include "nexus_util.h"

#include "nx_enclave_u.h"

extern sgx_enclave_id_t global_enclave_id;

/* nx_encode.c */
char *
metaname_bin2str(const struct uuid * uuid);

struct uuid *
metaname_str2bin(const char * str);

char *
filename_bin2str(const struct uuid * uuid);

struct uuid *
filename_str2bin(const char * str);


/* nexus_volume.c */
int
nexus_create_volume(char               * publickey_fpath,
                    struct supernode  ** p_supernode,
                    struct dirnode    ** p_root_dirnode,
                    struct volume_key ** p_sealed_volume_key);
