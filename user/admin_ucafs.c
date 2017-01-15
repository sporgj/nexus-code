#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include "cdefs.h"
#include "third/linenoise.h"
#include "third/sds.h"

#include "uc_sgx.h"
#include "uc_dirnode.h"
#include "uc_encode.h"
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

/**
 * We will parse the public in PEM format
 * @param path is the path to load from
 * @return 0 on success
 */
static int
new_supernode(const char * pubkey_path,
              const char * path,
              const char * user_root_path)
{
    int err = -1;
    sds dnode_path = NULL;
    char * main_dnode_fname = NULL;
    mbedtls_pk_context _ctx, *pk_ctx = &_ctx;
    uc_dirnode_t * dirnode = NULL;

    supernode_t * super = supernode_new();
    if (super == NULL) {
        uerror("supernode_new() returned NULL");
        return -1;
    }

    mbedtls_pk_init(pk_ctx);
    if (mbedtls_pk_parse_public_keyfile(pk_ctx, pubkey_path)) {
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

    if (!supernode_flush(super, path)) {
        uerror("supernode_write() failed");
        goto out;
    }

    /* now let's create the main dirnode */
    main_dnode_fname = metaname_bin2str(&super->root_dnode);

    dnode_path = sdsnew(user_root_path);
    dnode_path = sdscat(dnode_path, "/");
    dnode_path = sdscat(dnode_path, UCAFS_REPO_DIR);
    dnode_path = sdscat(dnode_path, main_dnode_fname);

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

    if (dnode_path) {
	sdsfree(dnode_path);
    }

    if (main_dnode_fname) {
	free(main_dnode_fname);
    }

    return err;
}

static int
login_enclave(const char * pubkey_path, const char * afs_repo_file)
{
    int err = -1;
    mbedtls_pk_context _ctx, *pk_ctx = &_ctx;
    supernode_t * super = supernode_from_file(afs_repo_file);
    if (super == NULL) {
        return -1;
    }

    mbedtls_pk_init(pk_ctx);
    if (mbedtls_pk_parse_public_keyfile(pk_ctx, pubkey_path)) {
        supernode_free(super);
        uerror("mbedtls_pk_parse_public_keyfile returned an error");
        return -1;
    }

#ifdef UCAFS_SGX
    ecall_ucafs_login(global_eid, &err, super, pk_ctx);
    if (err) {
        uerror("ecall_login returned %d", err);
        goto out;
    }
#endif

    err = 0;
out:
    supernode_free(super);
    return err;
}

int
main()
{
    int ret, err, nbytes, updated;
    FILE *fd1, *fd2;
    struct stat st;
    sds repo_file, main_dnode_path;

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
    if (err && new_supernode("profile/public_key", repo_file, repo_path)) {
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
