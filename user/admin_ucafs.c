#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "cdefs.h"
#include "third/linenoise.h"
#include "third/sds.h"

#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_sgx.h"
#include "uc_supernode.h"
#include "ucafs_header.h"

#ifdef __cplusplus
}
#endif

const char * repo_fname = "profile/repo.datum";

static char repo_path[1024];

supernode_t * super = NULL;

sgx_enclave_id_t global_eid = 0;

static int
shell()
{
    char * line;

    while ((line = linenoise("> ")) != NULL) {
        if (line[0] != '\0' && line[0] != '/') {
            linenoiseHistoryAdd(line);
        }

        free(line);
    }

    return 0;
}

/**
 * We will parse the public in PEM format
 * @param path is the path to load from
 * @return 0 on success
 */
static int
initialize_repository(const char * user_root_path)
{
    int err = -1;
    sds snode_path = NULL, dnode_path = NULL, repo_path;
    char * main_dnode_fname = NULL;
    mbedtls_pk_context _ctx, *pk_ctx = &_ctx;
    uc_dirnode_t * dirnode = NULL;
    struct stat st;

    supernode_t * super = supernode_new();
    if (super == NULL) {
        uerror("supernode_new() returned NULL");
        return -1;
    }

    mbedtls_pk_init(pk_ctx);
    if (mbedtls_pk_parse_public_keyfile(pk_ctx, CONFIG_PUBKEY)) {
        supernode_free(super);
        uerror("mbedtls_pk_parse_public_keyfile returned an error");
        return -1;
    }

#ifdef UCAFS_SGX
    ecall_initialize(global_eid, &err, super, pk_ctx);
    if (err) {
        uerror("ecall_initialize returned %d", err);
        goto out;
    }
#endif

    main_dnode_fname = metaname_bin2str(&super->root_dnode);

    /* create the paths for the dnode and the supernode */
    repo_path = sdsnew(user_root_path);
    repo_path = sdscat(repo_path, "/");
    repo_path = sdscat(repo_path, UCAFS_REPO_DIR);

    // lets make sure we have the folder available
    if (stat(repo_path, &st)) {
        if (mkdir(repo_path, S_IRWXG)) {
            uerror("mkdir FAILED: %s", repo_path);
            goto out;
        }
    }

    repo_path = sdscat(repo_path, "/");
    snode_path = repo_path, dnode_path = sdsdup(repo_path);

    snode_path = sdscat(snode_path, UCAFS_SUPER_FNAME);
    dnode_path = sdscat(dnode_path, main_dnode_fname);

    if (!supernode_write(super, snode_path)) {
        uerror("supernode_write() failed");
        goto out;
    }

    /* noe lets create the main dnode */
    dirnode = dirnode_new_alias(&super->root_dnode);
    if (!dirnode_write(dirnode, dnode_path)) {
        uerror("dirnode_write() failed");
        goto out;
    }

    err = 0;
out:
    mbedtls_pk_free(pk_ctx);
    supernode_free(super);
    if (dirnode) {
        dirnode_free(dirnode);
    }

    if (snode_path) {
        sdsfree(snode_path);
    }

    if (dnode_path) {
        sdsfree(dnode_path);
    }

    if (main_dnode_fname) {
        free(main_dnode_fname);
    }

    return err;
}

static int
login_enclave(const char * user_root_path)
{
    int err = -1;
    size_t olen = 0;
    uint8_t hash[32], buf[MBEDTLS_MPI_MAX_SIZE], nonce_a[32];
    sds snode_path = NULL;
    supernode_t * super;
    struct enclave_auth auth;
    mbedtls_sha256_context sha256_ctx;
    mbedtls_pk_context _ctx1, *public_k = &_ctx1, _ctx2, *private_k = &_ctx2,
                              _ctx3, *enclave_pubkey = &_ctx3;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    snode_path = ucafs_supernode_path(user_root_path);
    super = supernode_from_file(snode_path);
    if (super == NULL) {
        sdsfree(snode_path);
        return -1;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL,
                                0);
    if (err) {
        uerror("mbedtls_ctr_drbg_seed failed ret=%#x", err);
        goto out;
    }

    err = mbedtls_ctr_drbg_random(&ctr_drbg, nonce_a, sizeof(nonce_a));
    if (err) {
        uerror("mbedtls_ctr_drbg_random FAIELD ret=%#x", err);
        goto out;
    }

#ifdef UCAFS_SGX
    /* 1 - Challenge the enclave */
    ecall_ucafs_challenge(global_eid, &err, nonce_a, &auth);
    if (err) {
        uerror("enclave_challenge failed :(");
        goto out;
    }
#endif

    /* now compute our own version of the hash and respond to the enclave */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, nonce_a, sizeof(nonce_a));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t *)&auth, sizeof(auth));
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);

    /* parse the enclave public key */
    mbedtls_pk_init(enclave_pubkey);
    err = mbedtls_pk_parse_public_keyfile(enclave_pubkey,
                                          CONFIG_ENCLAVE_PUBKEY);
    if (err) {
        uerror("mbedtls_pk_parse_public_keyfile returned %d", err);
        goto out;
    }

    err = mbedtls_pk_verify(enclave_pubkey, MBEDTLS_MD_SHA256, hash, 0,
                            auth.signature, auth.sig_len);
    if (err) {
        uerror("mbedtls_pk_verify failed %d", err);
        goto out;
    }

    // now lets respond to the enclave
    /* parse the public key */
    mbedtls_pk_init(public_k);
    if ((err = mbedtls_pk_parse_public_keyfile(public_k, CONFIG_PUBKEY))) {
        uerror("mbedtls_pk_parse_public_keyfile returned %d", err);
        goto out;
    }

    /* parse the private key */
    mbedtls_pk_init(private_k);
    if ((err = mbedtls_pk_parse_keyfile(private_k, CONFIG_PRIVKEY, NULL))) {
        uerror("mbedtls_pk_parse returned %d", err);
        goto out;
    }

    if ((err = mbedtls_pk_sign(private_k, MBEDTLS_MD_SHA256, hash, 0, buf,
                               &olen, mbedtls_ctr_drbg_random, &ctr_drbg))) {
        uerror("mbedtls_pk_sign ret = %d", err);
        goto out;
    }

#ifdef UCAFS_SGX
    ecall_ucafs_response(global_eid, &err, super, public_k, buf, olen);
    if (err) {
        uerror("ecall_login returned %d", err);
        goto out;
    }
#endif

    err = 0;
out:
    supernode_free(super);

    if (snode_path) {
        sdsfree(snode_path);
    }

    return err;
}

static struct option long_options[]
    = { { "init", no_argument, NULL, 'i' }, { 0, 0, 0, 0 } };

int
main(int argc, char * argv[])
{
    int ret, err, nbytes, updated, opt_index = 0;
    char c;
    FILE *fd1, *fd2;
    struct stat st;

#ifdef UCAFS_SGX
    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        uerror("Could not open enclave: ret=%d", ret);
        return -1;
    }

    uinfo("Loaded enclave :)");
#endif

    fd1 = fopen(repo_fname, "rb");
    if (fd1 == NULL) {
        uerror("Could not open '%s'", repo_fname);
        return -1;
    }

    nbytes = fread(repo_path, 1, sizeof(repo_path), fd1);
    repo_path[strlen(repo_path) - 1] = '\0';

    while (1) {
        c = getopt_long(argc, argv, "i:", long_options, &opt_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'i':
            // if we get the --init flag, just initialize and quit
            return initialize_repository(repo_path);

        case -1:
            break;
        }
    }

    // else lets login into the enclave
    if (login_enclave(repo_path)) {
        goto out;
    }

    uinfo("Logged in :)");
    shell();

out:
    fclose(fd1);
    return ret;
}
