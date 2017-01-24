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
#include "third/log.h"
#include "third/sds.h"

#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_sgx.h"
#include "uc_supernode.h"
#include "ucafs_header.h"

#ifdef __cplusplus
}
#endif

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE

const char * repo_fname = "profile/repo.datum";

static char repo_path[1024];

supernode_t * super = NULL;
sds supernode_path = NULL;

sgx_enclave_id_t global_eid = 0;

static int
shell();

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

    log_info("Enclave initalized: %s", user_root_path);

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
    uint8_t hash[32], buf[MBEDTLS_MPI_MAX_SIZE], nonce_a[CONFIG_NONCE_SIZE];
    sds snode_path = NULL;
    auth_struct_t auth;
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

#ifdef UCAFS_SGX
    ecall_ucafs_response(global_eid, &err, super, public_k, buf, olen);
    if (err) {
        uerror("ecall_ucafs_response returned %d", err);
        goto out;
    }
#endif

    mbedtls_pk_free(public_k);
    mbedtls_pk_free(private_k);

    err = 0;
out:
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

    ecall_init_enclave(global_eid, &err);
    if (err) {
        uerror("Initializing enclave failed");
        goto out;
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

    supernode_path = ucafs_supernode_path(repo_path);

    uinfo("Logged in :)");
    shell();

out:
    fclose(fd1);
    return ret;
}

/***** the shell commands section of the program */
typedef enum {
    SHELL_ADD_USER,
    SHELL_DEL_USER,
    SHELL_LIST_USER
} shell_cmd_type_t;

typedef struct {
    shell_cmd_type_t type;
    int num_args;
    const char * cmd_str;
} shell_cmd_t;

static const shell_cmd_t shell_cmds[] = { { SHELL_ADD_USER, 2, "add" },
                                          { SHELL_DEL_USER, 2, "del" },
                                          { SHELL_LIST_USER, 0, "list" } };

#define MAX_SHELL_ARGS 5
typedef struct {
    shell_cmd_type_t type;
    uint16_t argc;
    char * args[MAX_SHELL_ARGS];
} shell_input_t;

static inline bool
is_ws(char c)
{
    return c == '\t' || c == ' ' || c == '\r';
}

static void
free_shell_input(shell_input_t * input)
{
    free(input);
}

void
shell_usage(shell_cmd_type_t type)
{
    const char * str;
    switch (type) {
    case SHELL_ADD_USER:
        str = "add username path_to_pubkey";
        break;
    case SHELL_DEL_USER:
        str = "del username path_to_pubkey";
        break;
    case SHELL_LIST_USER:
        str = "del username path_to_pubkey";
        break;
    default:
        return;
    }

    uerror("%s", str);
}

// rudimentary parsing of commands
static shell_input_t *
parse_command(char * stmt)
{
    char *temp, *str_buf;
    bool quotes = false;
    size_t i = 0, start = 0, stop = 0, max_args = 0, temp_len, j,
           len = strlen(stmt);
    shell_input_t * shell_input = NULL;

    while (1) {
    next_argument:
        if (i >= len) {
            break;
        }

        quotes = false;
        while (is_ws(*stmt) && i < len) {
            i++;
            stmt++;
        }

        // we've skipped all the whitespace, lets parse the type
        if (*stmt == '"') {
            quotes = true;
            stmt++;
            i++;
        }

        start = i;
        temp = stmt;

        while (i < len) {
            if ((quotes && *stmt == '"') || (!quotes && is_ws(*stmt))) {
                break;
            }

            i++;
            stmt++;
        }

        if (quotes) {
            // move to the next character
            i++;
            stmt++;
        }

        // exclude the " mark
        stop = i - (quotes ? 1 : 0) - 1;

        // if we have a shell input object, that means we are ready to
        // parse arguments
        if (shell_input) {
            goto parse_args;
        }

        // now lets get the command
        for (j = 0; j < sizeof(shell_cmds) / sizeof(shell_cmd_t); j++) {
            if (strncmp(shell_cmds[j].cmd_str, temp, stop - start) == 0) {
                shell_input = (shell_input_t *)calloc(1, sizeof(shell_input_t));
                if (shell_input == NULL) {
                    log_fatal("allocation failed\n");
                    return NULL;
                }

                shell_input->type = shell_cmds[j].type;
                shell_input->argc = 0;
                max_args = shell_cmds[j].num_args;
                goto next_argument;
            }
        }

        // if we are here, we couldn't detect the command type
        uerror("invalid command (%s)", temp);
        return NULL;

    parse_args:
        if (shell_input->argc >= max_args) {
            free_shell_input(shell_input);
            uerror("too many arguments (max = %zu)", max_args);
            return NULL;
        }

        shell_input->args[shell_input->argc++] = temp;
        *stmt++ = '\0';
    }

    if (shell_input->argc != max_args) {
        shell_usage(shell_input->type);
        free(shell_input);
        return NULL;
    }

    return shell_input;
}

static int
shell_add_user(const char * username, const char * pubkey)
{
    int ret = -1, len;
    uint8_t hash[CONFIG_SHA256_BUFLEN], buf[RSA_PUB_DER_MAX_BYTES], *c;
    mbedtls_pk_context _ctx, *pk_ctx = &_ctx;

    mbedtls_pk_init(pk_ctx);
    if ((ret = mbedtls_pk_parse_public_keyfile(pk_ctx, pubkey))) {
        uerror("mbedtls_pk_parse_public_keyfile error (ret=%#x)", ret);
        return -1;
    }

    len = mbedtls_pk_write_pubkey_der(pk_ctx, buf, sizeof(buf));
    if (len < 0) {
        uerror("mbedtls_pk_write_pubkey_der error (ret=%d)", len);
        return -1;
    }

    c = buf + sizeof(buf) - len - 1;
    mbedtls_sha256(c, len, hash, 0);

    if (supernode_add(super, username, hash)) {
        return -1;
    }

    /* save the supernode and call it a day */
    if (!supernode_write(super, supernode_path)) {
        return -1;
    }

    ret = 0;
out:
    return ret;
}

static void shell_list_users()
{
    supernode_list(super);
}

static int
shell()
{
    char * line;
    shell_input_t * input;

    if (supernode_mount(super)) {
        uerror("Exiting :(");
        return -1;
    }

    while ((line = linenoise("> ")) != NULL) {
        if (!line || (strlen(line) == 4
                      && (strstr(line, "exit") || strstr(line, "quit")))) {
            uinfo("bye :)\n");
            return 0;
        }

        if (line[0] != '\0' && line[0] != '/') {
            linenoiseHistoryAdd(line);
        }

        input = parse_command(line);

        if (input) {
            switch (input->type) {
            case SHELL_ADD_USER:
                shell_add_user(input->args[0], input->args[1]);
                break;
            case SHELL_DEL_USER:
                break;
            case SHELL_LIST_USER:
                shell_list_users();
                break;
            }

            free_shell_input(input);
        }

        free(line);
    }

    return 0;
}
