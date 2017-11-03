/**
 * File contains functions that manage Nexus volumes
 *
 * @author Judicael Djoko <jdb@djoko.me>
 */

#include "nx_untrusted.h"

int
nexus_create_volume(const char *     publickey_fpath,
                    const uint8_t ** dest_supernode,
                    int *            dest_supernode_size)
{
    /* 1 -- Read the public key into a buffer */

    /* 2 -- Call the enclave */

    return 0;
}

int
nexus_login_volume(const char * publickey_fpath, const char * supernode_fpath)
{
    /* 1 -- Read the public key into a buffer */

    /* 2 -- Read and parse the supernode */

    /* 3 -- Start the challenge-response with the enclave */

    return 0;
}

int
nexus_mount_volume(const char * supernode_fpath)
{
    /* 1 -- if not logged in, exit */

    /* 2 -- Read the supernode */

    /* 3 -- Call the enclave */

    return 0;
}

struct supernode *
supernode_new()
{
    struct supernode * supernode = NULL;

    supernode = calloc(1, sizeof(*supernode));
    if (supernode == NULL) {
        log_error("allocation error");
        return NULL;
    }

    generate_uuid(&supernode->uuid);
    generate_uuid(&supernode->root_uuid);

    return supernode;
}
