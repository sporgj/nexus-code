/**
 * Administers a NeXUS volume
 * @author Judicael B. Djoko <jbriand@cs.pitt.edu>
 */

#include "nexus_untrusted.h"

static char * metadata_path  = NULL;
static char * volkey_fpath = NULL;
static char * pubkey_fpath = NULL;
static char * privkey_fpath = NULL;

// this is temporary
#define ENCLAVE_PATH "./enclave/nx_enclave.signed.so"

static
int try_authenticating()
{
    int ret = -1;
    struct supernode * supernode = NULL;
    struct volumekey * volumekey = NULL;

    printf(". Trying to authenticate\n");

    ret = read_volume_metadata_files(
        metadata_path, volkey_fpath, &supernode, &volumekey);
    if (ret != 0) {
        log_error("could not read metadata files");
        goto out;
    }

    ret = nexus_login_volume(pubkey_fpath, privkey_fpath, supernode, volumekey);
    if (ret != 0) {
        log_error("could not login into volume");
        goto out;
    }

    printf(". Successful authentication :)\n");

    ret = 0;
out:
    nexus_free2(supernode);
    nexus_free2(volumekey);

    return ret;
}

int
main(int argc, char ** argv)
{
    int                ret          = -1;
    struct supernode * supernode    = NULL;
    struct dirnode *   root_dirnode = NULL;
    struct volumekey * volkey       = NULL;

    printf("NeXUS ADMIN tool\n");
    fflush(stdout);

    if (nexus_init_enclave(ENCLAVE_PATH)) {
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
    ret = nexus_create_volume(pubkey_fpath, &supernode, &root_dirnode, &volkey);
    if (ret != 0) {
        log_error("nexus_create_volume FAILED");
        goto out;
    }

    if (write_volume_metadata_files(
            supernode, root_dirnode, volkey, metadata_path, volkey_fpath)) {
        log_error("writing the metadata files FAILED");
        goto out;
    }

    if (try_authenticating()) {
        log_error("authentication failed, creating volume failed");
        goto out;
    }

    ret = 0;
out:
    nexus_free2(metadata_path);
    nexus_free2(volkey_fpath);
    nexus_free2(supernode);
    nexus_free2(root_dirnode);
    nexus_free2(volkey);

    return ret;
}
