/**
 * Administers a NeXUS volume
 * @author Judicael B. Djoko <jbriand@cs.pitt.edu>
 */

#if 0
#include "nexus_untrusted.h"

static char * metadata_path  = NULL;
static char * volkey_fpath = NULL;
static char * pubkey_fpath = NULL;
static char * privkey_fpath = NULL;

// this is temporary
#define ENCLAVE_PATH "./enclave/nx_enclave.signed.so"

int
write_volume_metadata_files(struct supernode * supernode,
                            struct dirnode *   root_dirnode,
                            struct volumekey * volkey,
                            const char *       metadata_path,
                            const char *       volumekey_fpath)
{
    int    ret             = -1;
    size_t size            = 0;
    char * dirnode_fname   = metaname_bin2str(&root_dirnode->header.uuid);
    char * supernode_fpath = strndup(metadata_path, PATH_MAX);
    char * dirnode_fpath   = strndup(metadata_path, PATH_MAX);

    supernode_fpath = filepath_from_name(supernode_fpath, NEXUS_FS_SUPERNODE_NAME);
    dirnode_fpath = filepath_from_name(dirnode_fpath, dirnode_fname);

    // write out the files now
    size = supernode->header.total_size;
    log_debug("Writing supernode [%zu bytes]: %s", size, supernode_fpath);
    if (write_file(supernode_fpath, (uint8_t *)supernode, size)) {
        goto out;
    }

    size = root_dirnode->header.total_size;
    log_debug("Writing dirnode [%zu bytes]: %s", size, dirnode_fpath);
    if (write_file(dirnode_fpath, (uint8_t *)root_dirnode, size)) {
        goto out;
    }

    size = sizeof(struct volumekey);
    log_debug("Writing volumekey [%zu bytes]: %s", size, volumekey_fpath);
    if (write_file(volumekey_fpath, (uint8_t *)volkey, size)) {
        goto out;
    }

    ret = 0;
out:
    if (dirnode_fname) {
        nexus_free(dirnode_fname);
    }

    if (dirnode_fpath) {
        nexus_free(dirnode_fpath);
    }

    if (supernode_fpath) {
        nexus_free(supernode_fpath);
    }

    return ret;
}

int
read_volume_metadata_files(const char *        metadata_path,
                           const char *        volumekey_fpath,
                           struct supernode ** p_supernode,
                           struct volumekey ** p_volumekey)
{
    int                ret       = -1;
    size_t             size      = 0;
    struct supernode * supernode = NULL;
    struct volumekey * volumekey = NULL;

    char * supernode_fpath = strndup(metadata_path, PATH_MAX);
    supernode_fpath = filepath_from_name(supernode_fpath, NEXUS_FS_SUPERNODE_NAME);

    ret = read_file(supernode_fpath, (uint8_t **)&supernode, &size);
    if (ret != 0) {
        log_error("reading supernode(%s) FAILED", supernode_fpath);
        goto out;
    }

    ret = read_file(volumekey_fpath, (uint8_t **)&volumekey, &size);
    if (ret != 0) {
        log_error("reading volumekey(%s) FAILED", volumekey_fpath);
        goto out;
    }

    *p_supernode = supernode;
    *p_volumekey = volumekey;

    ret = 0;
out:
    if (supernode_fpath) {
        nexus_free(supernode_fpath);
    }

    if (ret) {
        if (supernode) {
            nexus_free(supernode);
        }

        if (volumekey) {
            nexus_free(volumekey);
        }
    }

    return ret;
}

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
    if (supernode) {
        nexus_free(supernode);
    }

    if (volumekey) {
        nexus_free(volumekey);
    }

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

#endif
