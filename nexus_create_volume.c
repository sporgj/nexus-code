/**
 * Administers a NeXUS volume
 * @author Judicael B. Djoko <jbriand@cs.pitt.edu>
 */

#include "nexus_internal.h"

static char * metadata_path  = NULL;
static char * volkey_fpath = NULL;
static char * pubkey_fpath = NULL;
static char * privkey_fpath = NULL;

// this is temporary
#define ENCLAVE_PATH "nexus_enclave.signed.so"

int
main(int argc, char ** argv)
{
    int                ret          = -1;
    struct supernode * supernode    = NULL;
    struct dirnode *   root_dirnode = NULL;
    struct volumekey * volkey       = NULL;

    printf("Creating NEXUS volume... ");
    fflush(stdout);

    if (nexus_init()) {
        return -1;
    }

    if (argc < 4) {
        printf("usage: %s public_key private_key metatada_path volkey_fpath\n",
               argv[0]);
        fflush(stdout);
        return -1;
    }

    pubkey_fpath = strndup(argv[1], PATH_MAX);
    if (pubkey_fpath == NULL) {
        log_error("allocation error :(");
        goto out;
    }

    privkey_fpath = strndup(argv[2], PATH_MAX);
    if (privkey_fpath == NULL) {
        log_error("allocation error :(");
        goto out;
    }

    metadata_path = strndup(argv[3], PATH_MAX);
    if (metadata_path == NULL) {
        log_error("allocation error :(");
        goto out;
    }

    volkey_fpath = strndup(argv[4], PATH_MAX);
    if (volkey_fpath == NULL) {
        log_error("allocation error :(");
        goto out;
    }

    // call nexus_create_volume
    ret = nexus_create_volume(metadata_path, pubkey_fpath, volkey_fpath);
    if (ret != 0) {
        log_error("nexus_create_volume FAILED");
        goto out;
    }

    printf("OK\n");
    fflush(stdout);

    ret = 0;
out:
    if (metadata_path) {
        nexus_free(metadata_path);
    }

    if (volkey_fpath) {
        nexus_free(volkey_fpath);
    }

    if (supernode) {
        nexus_free(supernode);
    }

    if (root_dirnode) {
        nexus_free(root_dirnode);
    }

    if (volkey) {
        nexus_free(volkey);
    }

    return ret;
}

