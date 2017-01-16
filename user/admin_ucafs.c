#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

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

static int
initialize_repo(const char * user_root_path)
{
    int err = -1;
    mbedtls_pk_context _ctx, *pk_ctx = &_ctx;
    char * temp = NULL;
    sds supernode_path, repo_path, main_dnode_path;

    supernode_t * super = supernode_new();
    if (super == NULL) {
        uerror();
        return -1;
    }

    /* lets parse the public key */
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

    /* generate the paths to save the files to */
    repo_path = sdsnew(user_root_path);
    repo_path = sdscat(repo_path, "/");
    repo_path = sdscat(repo_path, UCAFS_REPO_DIR);
    repo_path = sdscat(repo_path, "/");

    supernode_path = sdsdup(repo_path);
    supernode_path = sdscat(supernode_path, UCAFS_SUPERNODE);

    temp = metaname_bin2str(&super->root_dnode);
    main_dnode_path = repo_path;
    main_dnode_path = sdscat(main_dnode_path, temp);

    /* now, create the dirnode and write both structures to disk */
    dirnode = dirnode_new_alias(&super->root_dnode);

    if (!supernode_flush(super, supernode_path)
        || !dirnode_write(dirnode, main_dnode_path)) {
        goto out;
    }

    err = 0;
out:
    if (supernode_path) {
        sdsfree(supernode_path);
    }

    if (repo_path) {
        sdsfree(repo_path);
    }

    supernode_free(super);

    if (dirnode) {
        dirnode_free(dirnode);
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

    // if we get the --init flag, just initialize and quit
    while (1) {
        c = getopt_long(argc, argv, "i:", long_options, &opt_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            if (long_options[opt_index].val = 'i') {
                // we are doing an init
                return initialize_repo(repo_path);
            }

            break;

        case -1:
            break;
        }
    }

#if 0
    /* 3 - We are trying to login */
    err = stat(repo_file, &st);
    if (err && new_supernode("profile/public_key", repo_file, repo_path)) {
        uerror("Error creating new supernode");
        goto out;
    }

    uinfo("Startup complete... :)");
    /* send the user to the cmd */
    shell();
#endif

out:
    fclose(fd1);
    sdsfree(repo_file);
    return ret;
}
