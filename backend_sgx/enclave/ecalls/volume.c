#include "../internal.h"

#include "nexus_key.h"

static struct nexus_hash      user_pubkey_hash;

static struct nexus_key       user_pubkey_key;

static struct nonce_challenge authentication_nonce;


static int
nx_create_volume(char * user_pubkey, struct nexus_uuid * supernode_uuid_out)
{
    struct supernode * supernode = NULL;

    int ret = -1;

    // this indirectly creates and stores the root dirnode
    supernode = supernode_create(user_pubkey);
    if (!supernode) {
        log_error("supernode_create FAILED\n");
        goto out;
    }

    ret = supernode_store(supernode, NULL, NULL);
    if (ret) {
        goto out;
    }

    nexus_uuid_copy(&supernode->my_uuid, supernode_uuid_out);

    ret = 0;
out:
    if (supernode) {
        supernode_free(supernode);
    }

    return ret;
}

int
ecall_create_volume(char              * user_pubkey_IN,
                    struct nexus_uuid * supernode_uuid_out,
                    struct nexus_uuid * volkey_bufuuid_out)
{
    int ret = -1;


    if (enclave_volumekey_gen()) {
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
        struct nexus_sealed_buf * sealed_volkey = NULL;

        ret = -1;

        sealed_volkey = enclave_volumekey_serialize();

        if (sealed_volkey == NULL) {
            log_error("could not serialize volumekey\n");
            goto out;
        }

        ret = nexus_sealed_buf_flush(sealed_volkey, volkey_bufuuid_out);
        if (ret) {
            nexus_sealed_buf_free(sealed_volkey);
            log_error("could not flush volkey uuid\n");
            goto out;
        }

        // TODO call nexus_sealed_buf_release
    }

    ret = 0;
out:
    enclave_volumekey_clear();

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
    int ret = -1;

    ret = __nexus_key_from_str(&user_pubkey_key, NEXUS_MBEDTLS_PUB_KEY, user_pubkey_IN);
    if (ret != 0) {
        log_error("could not parse the public key\n");
        return -1;
    }

    nexus_hash_generate(&user_pubkey_hash, user_pubkey_IN, strlen(user_pubkey_IN));

    return 0;
}

static void
generate_auth_challenge(struct nonce_challenge * challenge_out)
{
    sgx_read_rand((uint8_t *)&authentication_nonce, sizeof(struct nonce_challenge));

    memcpy(challenge_out, &authentication_nonce, sizeof(struct nonce_challenge));
}

int
ecall_authentication_challenge(char                   * user_pubkey_IN,
                               struct nexus_uuid      * volkey_bufuuid_in,
                               struct nonce_challenge * challenge_out)
{
    struct nexus_sealed_buf * volkey_sealed_buf = NULL;

    int ret = -1;


    clear_auth_pubkey();

    // parse the user's public key
    ret = load_auth_pubkey(user_pubkey_IN);
    if (ret) {
        log_error("load_auth_pubkey FAILED\n");
        return -1;
    }

    // get the volume key
    {
        volkey_sealed_buf = nexus_sealed_buf_create(volkey_bufuuid_in);
        if (volkey_sealed_buf == NULL) {
            log_error("nexus_sealed_buf_create() FAILED\n");
            goto err;
        }

        ret = enclave_volumekey_init(volkey_sealed_buf);
        if (ret != 0) {
            log_error("could not extract volumekey\n");
            goto err;
        }
    }

    generate_auth_challenge(challenge_out);

    nexus_sealed_buf_free(volkey_sealed_buf);

    return 0;
err:
    clear_auth_pubkey();

    if (volkey_sealed_buf) {
        nexus_sealed_buf_free(volkey_sealed_buf);
    }

    return -1;
}

int
ecall_authentication_response(struct nexus_uuid * supernode_bufuuid_in,
                              struct nexus_uuid * signature_bufuuid_in,
                              size_t              signature_len)
{
    struct nexus_crypto_buf * supernode_crypto_buf = NULL;

    struct nexus_raw_buf * signature_raw_buf = NULL;
    uint8_t              * signature_buffer  = NULL;

    uint8_t hash[32] = { 0 };

    int ret = -1;


    // get the supernode
    supernode_crypto_buf = nexus_crypto_buf_create(supernode_bufuuid_in);

    if (supernode_crypto_buf == NULL) {
        log_error("could not create crypto buffer\n");
        return -1;
    }

    // get the signature
    {
        size_t signature_buflen = 0;

        ret = -1;


        signature_raw_buf = nexus_raw_buf_create(signature_bufuuid_in);

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
        global_supernode = supernode_from_crypto_buf(supernode_crypto_buf);
        if (global_supernode == NULL) {
            log_error("invalid supernode\n");
            goto out;
        }

        ret = supernode_check_user_pubkey(global_supernode, &user_pubkey_hash);
        if (ret != 0) {
            supernode_free(global_supernode);
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

    clear_auth_pubkey();

    return ret;
}
