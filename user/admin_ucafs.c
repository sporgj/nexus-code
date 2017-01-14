#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include "cdefs.h"
#include "third/linenoise.h"
#include "third/sds.h"

#include "uc_sgx.h"
#include "uc_supernode.h"
#include "ucafs_header.h"

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

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE
/**
 * We will parse the public in PEM format
 * @param path is the path to load from
 * @return 0 on success
 */
static int
new_supernode(const char * pubkey_path, const char * path)
{
    int err = -1, len;
    mbedtls_pk_context _ctx, *pk_ctx = &_ctx;
    uint8_t buf[RSA_PUB_DER_MAX_BYTES] = {0}, * c;
    supernode_t * super = supernode_new();
    if (super == NULL) {
	uerror("supernode_new() returned NULL");
	goto out;
    }

    mbedtls_pk_init(pk_ctx);
    if (mbedtls_pk_parse_public_keyfile(pk_ctx, pubkey_path)) {
        uerror("mbedtls_pk_parse_public_keyfile returned an error");
        return -1;
    }

    if ((len = mbedtls_pk_write_pubkey_der(pk_ctx, buf, sizeof(buf))) < 0) {
        err = E_ERROR_CRYPTO;
        goto out;
    }

    c = buf + sizeof(buf) - len - 1;

#ifdef UCAFS_SGX
    ecall_initialize(global_eid, &err, super, pk_ctx);
    if (err) {
	uerror("ecall_initialize returned %d", err);
	goto out;
    }
#endif

    if (!supernode_flush(super, path)) {
	uerror("supernode_write() failed");
	goto out;
    }

    err = 0;
out:
    return err;
}

int
main()
{
    int ret, err, nbytes, updated;
    FILE *fd1, *fd2;
    struct stat st;
    sds repo_file;

#ifdef UCAFS_SGX
    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
			     &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
	uerror("Could not open enclave: ret=%d", ret);
	return -1;
    }

    uinfo(". Loaded enclave");
#endif

    fd1 = fopen(repo_fname, "rb");
    if (fd1 == NULL) {
        uerror("Could not open '%s'", repo_fname);
        return -1;
    }

    nbytes = fread(repo_path, 1, sizeof(repo_path), fd1);
    repo_path[strlen(repo_path) - 1] = '\0';

    /* 2 - Check if the repository exists */
    repo_file = sdsnew(repo_path);
    repo_file = sdscat(repo_file, "/");
    repo_file = sdscat(repo_file, UCAFS_REPO_FNAME);

    err = stat(repo_file, &st);
    if (err && new_supernode("profile/public_key", repo_file)) {
	uerror("Error creating new supernode");
	goto out;
    }

    uinfo("Startup complete... :)");
    /* send the user to the cmd */
    shell();

out:
    fclose(fd1);
    sdsfree(repo_file);
    return ret;
}
