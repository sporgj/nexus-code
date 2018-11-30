#include "../enclave_internal.h"


static struct nexus_hash      user_pubkey_hash;

static struct nexus_key       user_pubkey_key;

static struct nonce_challenge authentication_nonce;


static int
nx_create_volume(char * user_pubkey, struct nexus_uuid * supernode_uuid_out)
{
    struct nexus_supernode * supernode    = NULL;

    struct nexus_dirnode   * root_dirnode = NULL;

    int ret = -1;

    // creates the supernode & its accompanying usertable
    {
        ret = -1;

        supernode = supernode_create(user_pubkey);
        if (!supernode) {
            log_error("supernode_create FAILED\n");
            goto out;
        }

        // create the supernode file on disk
        if (buffer_layer_new(&supernode->my_uuid)) {
            log_error("could not create supernode file\n");
            goto out;
        }

        if (buffer_layer_new(&supernode->usertable->my_uuid)) {
            log_error("could not create usertable file\n");
            goto out;
        }

        ret = supernode_store(supernode, 0, NULL);

        if (ret) {
            log_error("storing the supernode FAILED\n");
            goto out;
        }
    }

    // root dirnode
    {
        ret = -1;

        root_dirnode = dirnode_create(&supernode->root_uuid, &supernode->root_uuid);
        if (root_dirnode == NULL) {
            goto out;
        }

        // make the dirnode's uuid the root uuid
        nexus_uuid_copy(&root_dirnode->root_uuid, &root_dirnode->my_uuid);

        if (buffer_layer_new(&root_dirnode->my_uuid)) {
            log_error("could not create root dirnode file\n");
            goto out;
        }

        ret = dirnode_store(&root_dirnode->my_uuid, root_dirnode, 0, NULL);

        if (ret != 0) {
            log_error("dirnode_store FAILED\n");
            goto out;
        }
    }

    nexus_uuid_copy(&supernode->my_uuid, supernode_uuid_out);

    ret = 0;
out:
    if (supernode) {
        supernode_free(supernode);
    }

    if (root_dirnode) {
        dirnode_free(root_dirnode);
    }

    return ret;
}

int
ecall_create_volume(char                    * user_pubkey_IN,
                    struct nexus_uuid       * supernode_uuid_out,
                    struct nexus_key_buffer * sealed_volkey_keybuf_out)
{
    int ret = -1;


    if (nexus_enclave_volumekey_generate()) {
        log_error("could not generate volumekey\n");
        return -1;
    }

    ret = nx_create_volume(user_pubkey_IN, supernode_uuid_out);
    if (ret) {
        log_error("nx_create_volume FAILED\n");
        goto out;
    }

    // write out the volumekey
    {
        struct nexus_key_buffer * key_buffer = NULL;

        ret = -1;

        key_buffer = nexus_enclave_volumekey_serialize();

        if (key_buffer == NULL) {
            log_error("could not serialize volumekey\n");
            goto out;
        }

        key_buffer_copy(key_buffer, sealed_volkey_keybuf_out);

        key_buffer_free(key_buffer);
    }
    
    //Stash Verifier INIT
    stashv_init(supernode_uuid_out);

    ret = 0;
out:
    nexus_enclave_volumekey_clear();

    return ret;
}

static void
clear_auth_pubkey()
{
    if (user_pubkey_key.key != NULL) {
        nexus_hash_clear(&user_pubkey_hash);

        nexus_free_key(&user_pubkey_key);
        user_pubkey_key.key = NULL;
    }
}

static int
load_auth_pubkey(char * user_pubkey_IN)
{
    if (__nexus_key_from_str(&user_pubkey_key, NEXUS_MBEDTLS_PUB_KEY, user_pubkey_IN)) {
        log_error("could not parse the public key\n");
        return -1;
    }

    return crypto_hash_pubkey(user_pubkey_IN, &user_pubkey_hash);
}

static void
generate_auth_challenge(struct nonce_challenge * challenge_out)
{
    sgx_read_rand((uint8_t *)&authentication_nonce, sizeof(struct nonce_challenge));

    memcpy(challenge_out, &authentication_nonce, sizeof(struct nonce_challenge));
}

int
ecall_authentication_challenge(char                    * user_pubkey_IN,
                               struct nexus_key_buffer * sealed_volkey_keybuf_out,
                               struct nonce_challenge  * challenge_OUT)
{
    int ret = -1;


    clear_auth_pubkey();

    // parse the user's public key
    ret = load_auth_pubkey(user_pubkey_IN);
    if (ret) {
        log_error("load_auth_pubkey FAILED\n");
        return -1;
    }

    // get the volume key
    ret = nexus_enclave_volumekey_load(sealed_volkey_keybuf_out);
    if (ret != 0) {
        log_error("could not extract volumekey\n");
        goto err;
    }

    generate_auth_challenge(challenge_OUT);

    return 0;
err:
    clear_auth_pubkey();

    return -1;
}

int
ecall_authentication_response(struct nexus_uuid * supernode_bufuuid_in,
                              uint8_t           * signature_buffer_in,
                              size_t              signature_len)
{
    struct nexus_crypto_buf * supernode_crypto_buf = NULL;

    struct nexus_raw_buf * signature_raw_buf = NULL;
    uint8_t              * signature_buffer  = NULL;

    uint8_t hash[32] = { 0 };

    int ret = -1;


    // get the supernode
    supernode_crypto_buf = nexus_crypto_buf_create(supernode_bufuuid_in, NEXUS_FREAD);

    if (supernode_crypto_buf == NULL) {
        log_error("could not create crypto buffer\n");
        return -1;
    }

    // get the signature
    {
        size_t signature_buflen = 0;

        ret = -1;


        signature_raw_buf = nexus_raw_buf_create(signature_buffer_in, signature_len);

        // use the signature buffer loaded in the raw_buf
        signature_buffer = nexus_raw_buf_get(signature_raw_buf, &signature_buflen);
        if (signature_buffer == NULL) {
            log_error("nexus_raw_buf_get() FAILED\n");
            goto out;
        }

        if (signature_buflen < signature_len) {
            log_error("the signature buffer is too small (actual=%zu, min=%zu)\n",
                      signature_buflen,
                      signature_len);
            goto out;
        }
    }

    // hash the necessary values
    {
        mbedtls_sha256_context sha_context;

        mbedtls_sha256_init(&sha_context);

        // sha256(nonce | volkey | supernode)
        mbedtls_sha256_starts(&sha_context, 0);

        mbedtls_sha256_update(&sha_context, authentication_nonce.bytes, sizeof(struct nonce_challenge));

        nexus_crypto_buf_sha256_exterior(supernode_crypto_buf, &sha_context);

        mbedtls_sha256_finish(&sha_context, hash);

        mbedtls_sha256_free(&sha_context);
    }

    // verify the signature
    {
        mbedtls_pk_context * pk = NULL;

        pk = (mbedtls_pk_context *)user_pubkey_key.key;

        ret = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, 0, signature_buffer, signature_len);

        if (ret != 0) {
            log_error("mbedtls_pk_verify FAILED (ret=0x%04x)\n", ret);
            goto out;
        }
    }

    // verify the supernode & user membership
    {
        ret = nexus_vfs_mount(supernode_crypto_buf);
        if (ret != 0) {
            log_error("invalid supernode\n");
            goto out;
        }

        ret = nexus_verfiy_pubkey(&user_pubkey_hash);
        if (ret != 0) {
            nexus_vfs_deinit();
            log_error("could not verify the user's public key\n");
            goto out;
        }
    }

    ret = 0;
out:
    if (signature_raw_buf) {
        nexus_raw_buf_free(signature_raw_buf);
    }

    if (supernode_crypto_buf) {
        nexus_crypto_buf_free(supernode_crypto_buf);
    }

    if (ret != 0) {
        // on error, clear the loaded volumekey
        nexus_enclave_volumekey_clear();
    }

    clear_auth_pubkey();

    return ret;
}
