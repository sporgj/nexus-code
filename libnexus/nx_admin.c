/**
 * Administers a NeXUS volume
 * @author Judicael B. Djoko <jbriand@cs.pitt.edu>
 */

#include "nexus_untrusted.h"

static char * metadata_path  = NULL;
static char * volkey_fpath = NULL;
static char * pubkey_fpath = NULL;

static int
write_metadata_files(struct supernode *  supernode,
                     struct dirnode *    root_dirnode,
                     struct volume_key * volkey)
{
    int    ret             = -1;
    size_t nbytes          = 0;
    size_t size            = 0;
    FILE * fd              = NULL;
    char * dirnode_fname   = metaname_bin2str(&root_dirnode->header.uuid);
    char * supernode_fpath = strndup(metadata_path, PATH_MAX);
    char * dirnode_fpath   = strndup(metadata_path, PATH_MAX);

    supernode_fpath = pathjoin(supernode_fpath, NEXUS_FS_SUPERNODE_NAME);
    dirnode_fpath = pathjoin(dirnode_fpath, dirnode_fname);

    // write out the files now
    log_debug("Writing supernode: %s", supernode_fpath);
    fd = fopen(supernode_fpath, "wb");
    if (fd == NULL) {
        log_error("fopen(%s) FAILED", supernode_fpath);
        goto out;
    }

    size   = supernode->header.total_size;
    nbytes = fwrite(supernode, 1, size, fd);
    if (nbytes != size) {
        log_error("fwrite FAILED. tried=%zu, got=%zu", size, nbytes);
        goto out;
    }

    fclose(fd);

    log_debug("Writing dirnode: %s", dirnode_fpath);
    fd = fopen(dirnode_fpath, "wb");
    if (fd == NULL) {
        log_error("fopen(%s) FAILED", dirnode_fpath);
        goto out;
    }

    size   = root_dirnode->header.total_size;
    nbytes = fwrite(root_dirnode, 1, size, fd);
    if (nbytes != size) {
        log_error("fwrite FAILED. tried=%zu, got=%zu", size, nbytes);
        goto out;
    }

    ret = 0;
out:
    if (fd) {
        fclose(fd);
    }

    nexus_free2(dirnode_fname);
    nexus_free2(dirnode_fpath);
    nexus_free2(supernode_fpath);

    return ret;
}

// this is temporary
#define ENCLAVE_PATH "./enclave/nx_enclave.signed.so"

int
main(int argc, char ** argv)
{
    int                 ret          = -1;
    struct supernode *  supernode    = NULL;
    struct dirnode *    root_dirnode = NULL;
    struct volume_key * volkey       = NULL;

    printf("NeXUS ADMIN tool\n");
    fflush(stdout);

    if (nexus_init_enclave(ENCLAVE_PATH)) {
        return -1;
    }

    if (argc < 3) {
        printf("usage: %s public_key metatada_path volkey_fpath\n", argv[0]);
        fflush(stdout);
        return -1;
    }

    pubkey_fpath = strndup(argv[1], PATH_MAX);
    if (pubkey_fpath == NULL) {
        log_error("allocation error :(");
        goto out;
    }

    metadata_path = strndup(argv[2], PATH_MAX);
    if (metadata_path == NULL) {
        log_error("allocation error :(");
        goto out;
    }

    volkey_fpath = strndup(argv[3], PATH_MAX);
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

    if (write_metadata_files(supernode, root_dirnode, volkey)) {
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
