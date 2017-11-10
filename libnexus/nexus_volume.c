/**
 * File contains functions that manage Nexus volumes
 *
 * @author Judicael Djoko <jdb@djoko.me>
 */
#include <sys/stat.h>

#include "nexus_untrusted.h"

sgx_enclave_id_t global_enclave_id = 0;

void
ocall_print(const char * str)
{
    printf("enclave: %s", str);
    fflush(stdout);
}

static char *
read_pubkey_file(char * publickey_fpath, size_t * p_flen)
{
    int         ret        = -1;
    size_t      nbytes     = 0;
    size_t      flen       = 0;
    FILE *      fd         = NULL;
    char *      pubkey_buf = NULL;
    struct stat st         = { 0 };

    /* 1 -- Read the public key into a buffer */
    if (stat(publickey_fpath, &st)) {
        log_error("file not found (%s)", publickey_fpath);
        return NULL;
    }

    flen = st.st_size;

    fd = fopen(publickey_fpath, "rb");
    if (fd == NULL) {
        log_error("fopen('%s') FAILED", publickey_fpath);
        return NULL;
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

    *p_flen = flen;
    ret     = 0;
exit:
    fclose(fd);

    if (ret) {
        nexus_free2(pubkey_buf); // gets set to NULL
    }

    return pubkey_buf;
}

int
nexus_init_enclave(const char * enclave_fpath)
{
    int ret     = -1;
    int updated = 0;
    int err     = 0;

    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(enclave_fpath,
                             SGX_DEBUG_FLAG,
                             &token,
                             &updated,
                             &global_enclave_id,
                             NULL);
    if (ret != SGX_SUCCESS) {
        log_error("Could not open enclave: ret=%#x", ret);
        return -1;
    }

    ecall_init_enclave(global_enclave_id, &err);
    if (err != 0) {
        log_error("Initializing enclave failed");
        return -1;
    }

    return 0;
}

int
nexus_create_volume(char *               publickey_fpath,
                    struct supernode **  p_supernode,
                    struct dirnode **    p_root_dirnode,
                    struct volume_key ** p_sealed_volume_key)
{
    int                 ret          = -1;
    size_t              pubkey_len   = 0;
    char *              pubkey_buf   = NULL;
    struct supernode *  supernode    = NULL;
    struct dirnode *    root_dirnode = NULL;
    struct volume_key * volkey       = NULL;
    struct uuid         supernode_uuid;
    struct uuid         root_uuid;

    pubkey_buf = read_pubkey_file(publickey_fpath, &pubkey_len);
    if (pubkey_buf == NULL) {
        log_error("could not read public key file");
        goto out;
    }

    /* 2 -- allocate our structs and call the enclave */
    supernode    = (struct supernode *)calloc(1, sizeof(struct supernode));
    root_dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    volkey       = (struct volume_key *)calloc(1, sizeof(struct volume_key));
    if (supernode == NULL || root_dirnode == NULL || volkey == NULL) {
        log_error("allocation error");
        goto out;
    }

    nexus_uuid(&supernode_uuid);
    nexus_uuid(&root_uuid);

    ecall_create_volume(global_enclave_id,
                        &ret,
                        &supernode_uuid,
                        &root_uuid,
                        pubkey_buf,
                        pubkey_len,
                        supernode,
                        root_dirnode,
                        volkey);

    if (ret != 0) {
        log_error("ecall_create_volume FAILED ret=%d", ret);
        goto out;
    }

    *p_supernode         = supernode;
    *p_root_dirnode      = root_dirnode;
    *p_sealed_volume_key = volkey;

    ret = 0;
out:
    if (pubkey_buf) {
        free(pubkey_buf);
    }

    if (ret) {
        nexus_free2(supernode);
        nexus_free2(root_dirnode);
        nexus_free2(volkey);
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
