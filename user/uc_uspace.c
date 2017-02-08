#include <string.h>

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include "uc_sgx.h"
#include "uc_supernode.h"
#include "uc_vfs.h"

#include "cdefs.h"
#include "uc_uspace.h"

char * global_supernode_paths[MAX_SUPERNODE_PATHS] = { NULL };
size_t global_supernode_count = 0;

supernode_t * global_supernode_object = NULL;

int
ucafs_init_uspace()
{
    int ret;

    if ((ret = metadata_init())) {
        return ret;
    }

    return ret;
}

int
ucafs_exit_uspace()
{
    metadata_exit();

    return 0;
}

static inline sds
repo_path(const char * root_path)
{
    sds rv = sdsnew(root_path);
    rv = sdscat(rv, "/");
    rv = sdscat(rv, UCAFS_REPO_DIR);
    rv = sdscat(rv, "/");

    return rv;
}

sds
ucafs_supernode_path(const char * root_path)
{
    sds rv = repo_path(root_path);
    rv = sdscat(rv, UCAFS_SUPER_FNAME);

    return rv;
}

sds
ucafs_metadata_path(const char * root_path, const char * meta_fname)
{
    sds rv = repo_path(root_path);
    rv = sdscat(rv, meta_fname);

    return rv;
}

static inline void
trim(char * str)
{
    while (*str != '\0') {
        if (*str == '\n') {
            *str = '\0';
            break;
        }

        str++;
    }
}

int
ucafs_login(const char * user_root_path)
{
#ifdef UCAFS_SGX
    int err = -1;
    size_t olen = 0;
    uint8_t hash[32], buf[MBEDTLS_MPI_MAX_SIZE], nonce_a[CONFIG_NONCE_SIZE];
    sds snode_path = NULL;
    auth_struct_t auth;
    mbedtls_sha256_context sha256_ctx;
    mbedtls_pk_context _ctx1, *public_k = &_ctx1, _ctx2, *private_k = &_ctx2,
                              _ctx3, *enclave_pubkey = &_ctx3;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    snode_path = ucafs_supernode_path(user_root_path);
    supernode_t * super = supernode_from_file(snode_path);
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

    /* 1 - Challenge the enclave */
    ecall_ucafs_challenge(global_eid, &err, nonce_a, &auth);
    if (err) {
        uerror("enclave_challenge failed :(");
        goto out;
    }

    /* now compute our own version of the hash and respond to the enclave */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, nonce_a, sizeof(nonce_a));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t *)&auth,
                          sizeof(auth_payload_t));
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

    mbedtls_pk_free(enclave_pubkey);

    // TODO verify that measurement matches

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

    /* compute a new hash */
    mbedtls_sha256(auth.nonce, CONFIG_NONCE_SIZE, hash, 0);
    if ((err = mbedtls_pk_sign(private_k, MBEDTLS_MD_SHA256, hash, 0, buf,
                               &olen, mbedtls_ctr_drbg_random, &ctr_drbg))) {
        uerror("mbedtls_pk_sign ret = %d", err);
        goto out;
    }

    ecall_ucafs_response(global_eid, &err, super, public_k, buf, olen);
    if (err) {
        uerror("ecall_ucafs_response returned %d", err);
        goto out;
    }

    mbedtls_pk_free(public_k);
    mbedtls_pk_free(private_k);

    global_supernode_object = super;

    err = 0;
out:
    if (snode_path) {
        sdsfree(snode_path);
    }

    return err;
#else
    return 0;
#endif
}

int
ucafs_init_enclave()
{
    int ret, updated, err;
#ifdef UCAFS_SGX
    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        uerror("Could not open enclave: ret=%d", ret);
        return -1;
    }

    ecall_init_enclave(global_eid, &err);
    if (err) {
        uerror("Initializing enclave failed");
        return -1;
    }

    uinfo("Loaded enclave :)");
    return 0;
#else
    return 0;
#endif
}

int
ucafs_launch(const char * mount_file_path)
{
    int ret = -1;
    ssize_t sz;
    size_t n, count = 0;
    FILE * fd1;
    char * repo_path = NULL;

    fd1 = fopen(mount_file_path, "rb");
    if (fd1 == NULL) {
        uerror("Could not open '%s'", mount_file_path);
        return -1;
    }

    /* read each line and have them added to the list of paths */
    while (((sz = getline(&repo_path, &n, fd1)) != -1)
           && count < MAX_SUPERNODE_PATHS) {
        trim(repo_path);

        if (count == 0 && ucafs_login(repo_path)) {
            uerror("Could not log in :(");
            return -1;
        }

        if (vfs_mount(repo_path)) {
            /* this should almost never happen */
            if (count == 0) {
                log_error("Mounting login supernode failed :(, can't continue");
                return -1;
            }

            /* for getline to work safely */
            free(repo_path);
            repo_path = NULL;
            continue;
        }

        global_supernode_paths[count++] = repo_path;

        repo_path = NULL;
    }

    global_supernode_count = count;

    fclose(fd1);
    return 0;
}
