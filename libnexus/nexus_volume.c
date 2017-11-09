/**
 * File contains functions that manage Nexus volumes
 *
 * @author Judicael Djoko <jdb@djoko.me>
 */
#include <sys/stat.h>

#include "nx_untrusted.h"

int
nexus_create_volume(const char *     publickey_fpath,
                    const uint8_t ** dest_supernode,
                    const uint8_t ** dest_root_dirnode,
                    int *            dest_supernode_size)
{
    int         ret        = -1;
    size_t      flen       = 0;
    size_t      nbytes     = 0;
    char *      pubkey_buf = NULL;
    FILE *      fd         = NULL;
    struct stat st;

    /* 1 -- Read the public key into a buffer */
    if (stat(publickey_fpath, &st)) {
        log_error("file not found (%s)", publickey_fpath);
        return -1;
    }

    flen = st.st_size;

    fd = fopen(publickey_fpath, "rb");
    if (fd == NULL) {
        log_error("fopen('%s') FAILED", publickey_fpath);
        return -1;
    }

    pubkey_buf = calloc(1, flen);
    if (pubkey_buf == NULL) {
        log_error("allocation error");
        goto exit;
    }

    nbytes = fread(pubkey_buf, 1, flen, fd);
    if (nbytes != flen) {
        log_error("read_error. tried=%zu, got=%zu", flen, nbytes);
        goto exit;
    }

    /* 2 -- Call the enclave */

    ret = 0;
exit:
    if (fd) {
        fclose(fd);
    }

    if (pubkey_buf) {
        free(pubkey_buf);
    }

    return ret;
}

int
nexus_login_volume(const char * publickey_fpath,
                   const char * privatekey_fpath,
                   const char * supernode_fpath)
{
    /* 1 -- Read the private key into a buffer */

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
