#include "ucafs_sgx.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE

bool enclave_is_logged_in = false, is_admin_program_running = false;

supernode_t user_supernode = { 0 }, init_supernode = { 0 };
pubkey_t * user_pubkey = (pubkey_t *)&user_supernode.owner_pubkey;

snode_head_t supernode_list_head = SLIST_HEAD_INITIALIZER(NULL),
             *snode_list = &supernode_list_head;

/* the enclave private key */
static const char enclave_private_key[]
    = "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIIEpgIBAAKCAQEAxq5vDLLSw/IM0QVQb+HWOFEjWl8YZDCm3a6Q9O/UkdrMweFf\n"
      "cIPMfNqW4FGsO7iKzmDAoIiAebqbfExCudnbzxCcFLYzLtECyfEeBIrmoR/Cfcxq\n"
      "Nl+qol5+eijZvQtMeXCg1i59g9xKNbAKTa1S5QlcDnfyKttGJ9I1ngElgyAYjzJ2\n"
      "3TaFQgPhVB7u4LFd8DFlPouiyl1QWfmGhEH/E4E6Lguc45UGCQrMYfIIm0lQ83cT\n"
      "7y/1K5r0Lyv2daAEHmJVupnZPXt1s+OMkK7GLOVglgDowuHxittWqkUP+ePUMkG8\n"
      "ukzeNSyNqvwOBhXeNW/FZ8y7XbiO6kM59mJkqQIDAQABAoIBAQCRfTS2sNBkSoCW\n"
      "I3UWqOLM1KW1zMM4wuO+m9Fse59Gu1mLdDUGWI1KtGsdktEz3lxO6kzEgZDLExo+\n"
      "+D04iU9MHxacmBt84fNP27AmlWxzeqVap3DzpjR2uAmX/QgNRhPXLeGpVdv1zj/N\n"
      "dr7kyNJWA/eUZMNCHNYP3QAEV0SX8oMv6pVrKSzt22mXl4wzrwbx4HzgRzhkERbE\n"
      "p4bL3+sAvpGv5fdDSHR5MmGQEggG7fCyHXpoWaH7Ucb4JpfP7mwlf5/Ex7KimWaN\n"
      "ja4Rcqs3YCm1cjDzHFrFUtGij+t56fGFdaEgxJOfwUYl5UYMdbXLGlyhvLkzV6L3\n"
      "Y8thK44xAoGBAO1DMm3jKrCyqNnYdswm6xqdCc1mgHRwoEqdo5qxXIaQLhTYApat\n"
      "0JlI0vp3v6YRoVtoPul8NmbfmZmz/FWXqUUMD/C8BE/atGWLirJ+XrqDu/WEB8Wm\n"
      "ZWN18FOYLnMcgYEXoy0q33HqpeflscDaJgSLqx9vzQfQtr/HROctv/b1AoGBANZf\n"
      "O0w3pjX1m4usUjd1gSMoyCA6Yw4oA7Vi0DKdFcuN6mzclcJVqwjgw3q9HlfioKtL\n"
      "gVQowLCpMod0kYeUWqh0VK53qQwlEILAAD1q3+tuNcWo8i81OxvTzHUIBPznrrRi\n"
      "Upt/Eu3lzFzKbidfvA1xzKwtaNzdaDHWdSxuGF5lAoGBAIlV3yfqWXikQcavXLx5\n"
      "PpdOFTF2xp4f3zixnNTbGzKs3G+mRYFQpTFFDRJ8JEwNYngVlGz0QE012qQ0obgt\n"
      "rIZSIBv5yQksEEXDCwqcyVpvDGpl/VW0JnX2+6B3s1NgSboeo45uhZ5b86KSu1xl\n"
      "KaJx8iClR2nhrxa9Uq36NmbNAoGBAIk/iXB/xIuRhxfCqRTWx2oiRxbTKu46Uj2E\n"
      "WTW+euDLKIawJ7W3MXzKonznrhCoiSOCgPfH665vdWliCXabVfu6FylodTPQWyTL\n"
      "Fpw728cY1ZaKVxxAYWqsjJ91FfRxxNm6hZcGobDsSo4yEJpm4bhd3qNxo0yc+IPI\n"
      "AVcD2dg9AoGBAIGp6rGuLinWHFY8xHNyMaCy1A9OTMn3gLPJ/a8swEk+ncr1JQ/t\n"
      "X384AWK25gneyq2qTOGjVdNB4O6jwegH+Fgl9QJB9odJYwd3sqM44pRCdTR0/jBc\n"
      "bElz7XnBfi3zRf0Empc6feiCK5ptxcffEgtIWYLnj4r3cshr70FolRWm\n"
      "-----END RSA PRIVATE KEY-----\n";

static const size_t enclave_private_key_len = sizeof(enclave_private_key);

enum auth_stage { CHALLENGE, RESPONSE, COMPLETE };

enum auth_stage auth_stage = CHALLENGE;

typedef enum {
    SUPERNODE_NONE,
    SUPERNODE_ENCRYPT,
    SUPERNODE_DECRYPT
} snode_crypto_t;

supernode_t *
find_supernode(shadow_t * root_dnode)
{
    int ret;
    supernode_t * super;
    snode_entry_t * snode_entry;

    ret = memcmp(root_dnode, &user_supernode.root_dnode, sizeof(shadow_t));
    if (ret == 0) {
        return &user_supernode;
    }

    /* iterate supernodes and find the suitable one */
    SLIST_FOREACH(snode_entry, snode_list, next_entry)
    {
        super = &snode_entry->super;
        if (memcmp(root_dnode, &super->root_dnode, sizeof(shadow_t))) {
            continue;
        }

        // if we are here, the current user is the owner
        return super;
    }

    // then return the init supernode
    if (is_admin_program_running) {
        return &init_supernode;
    }

    return NULL;
}

unsigned char buf[RSA_PUB_DER_MAX_BYTES];
/* store the hash of the user's public key */
static int
sha256_pubkey(mbedtls_pk_context * user_pubkey_ctx, uint8_t * pubkey_hash)
{
    unsigned char * c;
    int len = mbedtls_pk_write_pubkey_der(user_pubkey_ctx, buf, sizeof(buf));
    if (len < 0) {
        return E_ERROR_CRYPTO;
    }

    c = buf + sizeof(buf) - len - 1;

    mbedtls_sha256(c, len, pubkey_hash, 0);
    return 0;
}

static int
supernode_hash(supernode_t * super,
               crypto_context_t * crypto_ctx,
               crypto_mac_t * mac,
               snode_crypto_t op)
{
    int len, bytes_left;
    crypto_iv_t iv;
    size_t off = 0;
    mbedtls_md_context_t _h, *hmac_ctx = &_h;
    mbedtls_aes_context _a, *aes_ctx = &_a;
    uint8_t buf[E_CRYPTO_BUFFER_LEN] = { 0 }, stream_block[16], *users_buf;

    /* generate the hmac */
    mbedtls_md_init(hmac_ctx);
    mbedtls_md_setup(hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                           CRYPTO_MAC_KEY_SIZE);

    mbedtls_md_hmac_update(hmac_ctx, (uint8_t *)super,
                           sizeof(supernode_payload_t));

    /* if there're no users, just close the hmac and call it a day */
    if (super->user_count == 0) {
        goto out;
    }

    // lets go through every user
    mbedtls_aes_init(aes_ctx);
    mbedtls_aes_setkey_enc(aes_ctx, (uint8_t *)&crypto_ctx->ekey,
                           CRYPTO_AES_KEY_SIZE_BITS);

    /* setup the IV */
    if (op == SUPERNODE_ENCRYPT) {
        sgx_read_rand((uint8_t *)&crypto_ctx->iv, sizeof(crypto_iv_t));
    }

    memcpy(&iv, &crypto_ctx->iv, sizeof(crypto_iv_t));

    users_buf = super->users_buffer;
    bytes_left = super->users_buflen;
    while (bytes_left > 0) {
        // lets reuse buf
        len = MIN(sizeof(buf), bytes_left);
        memcpy(buf, users_buf, len);

        if (op == SUPERNODE_ENCRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, len, &off, iv.bytes, stream_block,
                                  buf, buf);
        }

        mbedtls_md_hmac_update(hmac_ctx, buf, len);

        if (op == SUPERNODE_DECRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, len, &off, iv.bytes, stream_block,
                                  buf, buf);
        }

        memcpy(users_buf, buf, len);

        users_buf += len;
        bytes_left -= len;
    }

    mbedtls_aes_free(aes_ctx);
out:
    mbedtls_md_hmac_finish(hmac_ctx, (uint8_t *)mac);
    mbedtls_md_free(hmac_ctx);

    return 0;
}

int
ecall_initialize(supernode_t * super, char * pubkey_str, size_t keylen)
{
    int err = -1, len;
    supernode_t _super;
    mbedtls_pk_context _, * user_pubkey_ctx = &_;
    crypto_ekey_t * skey;
    crypto_context_t * crypto_ctx = &_super.crypto_ctx;

    /* initialize the data */
    memcpy(&_super, super, sizeof(supernode_t));
    _super.user_count = 0;
    _super.users_buflen = 0;
    sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));

    /* parse the public key string */
    mbedtls_pk_init(user_pubkey_ctx);
    if (mbedtls_pk_parse_public_key(user_pubkey_ctx, pubkey_str, keylen)) {
        return -1;
    }

    sha256_pubkey(user_pubkey_ctx, _super.owner_pubkey);
    mbedtls_pk_free(user_pubkey_ctx);

    /* hash it */
    if (supernode_hash(&_super, crypto_ctx, &crypto_ctx->mac,
                       SUPERNODE_ENCRYPT)) {
        return E_ERROR_CRYPTO;
    }

    skey = derive_skey2(__enclave_key__, &_super.root_dnode, &_super.uuid);
    if (skey == NULL) {
        return -1;
    }

    // TODO add flag for init sessions
    memcpy(&init_supernode, &_super, sizeof(supernode_t));
    is_admin_program_running = true;

    enclave_crypto_ekey(&crypto_ctx->ekey, skey, UC_ENCRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, skey, UC_ENCRYPT);

    memcpy(super, &_super, sizeof(supernode_t));

    free(skey);

    return 0;
}

static int
custom_drbg(void * out, unsigned char * seed, size_t len, size_t * olen)
{
    sgx_read_rand(out, len);
    *olen = len;

    return 0;
}

uint8_t auth_hash[32], na_hash[32];

/**
 * Generates the "challenge" portion of the test.
 */
int
ecall_ucafs_challenge(uint8_t * n_a, auth_struct_t * auth)
{
    int err = -1;
    uint8_t nonce_a[CONFIG_NONCE_SIZE];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_pk_context pk;

    if (auth_stage != CHALLENGE) {
        return -1;
    }

    /* initialize the rng */
    mbedtls_entropy_init(&entropy);
    mbedtls_entropy_add_source(&entropy, custom_drbg, NULL, 1,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL,
                              0)) {
        goto out;
    }

    /* initialize the private key */
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_key(&pk, enclave_private_key, enclave_private_key_len,
                             NULL, 0)) {
        goto out;
    }

    memcpy(nonce_a, n_a, sizeof(nonce_a));

    /* compute the hash of the nonce and our measurement */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, nonce_a, CONFIG_NONCE_SIZE);
    mbedtls_sha256_update(&sha256_ctx, (uint8_t *)&enclave_auth_data,
                          sizeof(auth_payload_t));
    mbedtls_sha256_finish(&sha256_ctx, auth_hash);
    mbedtls_sha256_free(&sha256_ctx);

    mbedtls_sha256(enclave_auth_data.nonce, sizeof(nonce_a), na_hash, 0);

    /* sign the structure and return */
    if (mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, auth_hash, 0, auth->signature,
                        &auth->sig_len, mbedtls_ctr_drbg_random, &ctr_drbg)) {
        goto out;
    }

    memcpy(auth, &enclave_auth_data, sizeof(auth_payload_t));
    auth_stage = RESPONSE;

    err = 0;
out:
    return err;
}

static int
usgx_ucafs_response(supernode_t * super,
                    char * pubkey_str,
                    size_t keylen,
                    uint8_t * user_signature,
                    size_t sig_len)
{
    int err = E_ERROR_ERROR, len;
    crypto_context_t _ctx, *crypto_ctx = &_ctx;
    crypto_mac_t mac;
    crypto_ekey_t * skey = NULL;
    mbedtls_pk_context _, * user_pubkey_ctx = &_;
    unsigned char hash[CONFIG_SHA256_BUFLEN];

    if (auth_stage != RESPONSE || sig_len > MBEDTLS_MPI_MAX_SIZE) {
        return -1;
    }

    /* parse the public key string */
    mbedtls_pk_init(user_pubkey_ctx);
    if (mbedtls_pk_parse_public_key(user_pubkey_ctx, pubkey_str, keylen)) {
        return -1;
    }

    /* 1 - Verify the public key matches the private key */
    if (mbedtls_pk_verify(user_pubkey_ctx, MBEDTLS_MD_SHA256, na_hash, 0,
                          user_signature, sig_len)) {
        goto out;
    }

    /* 2 - Verify the supernode has not been tampered and was created with the
     * specified public key */

    skey = derive_skey2(__enclave_key__, &super->root_dnode, &super->uuid);
    if (skey == NULL) {
        return -1;
    }

    err = E_ERROR_LOGIN;
    memcpy(crypto_ctx, &super->crypto_ctx, sizeof(crypto_context_t));
    enclave_crypto_ekey(&crypto_ctx->ekey, skey, UC_DECRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, skey, UC_DECRYPT);

    supernode_hash(super, crypto_ctx, &mac, SUPERNODE_NONE);
    if (memcmp(&crypto_ctx->mac, &mac, sizeof(crypto_mac_t))) {
        goto out;
    }

    // TODO this might be an overkill, we could just use pubkey_str
    sha256_pubkey(user_pubkey_ctx, hash);
    if (memcmp(&super->owner_pubkey, hash, sizeof(hash))) {
        goto out;
    }

    /* now copy the super structure */
    memcpy(&user_supernode, super, sizeof(supernode_t));

    auth_stage = COMPLETE;
    enclave_is_logged_in = true;

    err = 0;
out:
    if (skey) {
        free(skey);
    }

    mbedtls_pk_free(user_pubkey_ctx);

    return err;
}

int
ecall_ucafs_response(supernode_t * super,
                     char * pubkey_str,
                     size_t keylen,
                     uint8_t * user_signature,
                     size_t sig_len)
{
    return usgx_ucafs_response(super, pubkey_str, keylen, user_signature,
                               sig_len);
}

int
ecall_supernode_crypto(supernode_t * super, seal_op_t op)
{
    int ret = -1, err = -1;
    supernode_t _super;
    crypto_context_t * crypto_ctx;
    snode_crypto_t super_op
        = (op == CRYPTO_SEAL ? SUPERNODE_ENCRYPT : SUPERNODE_DECRYPT);

    /* copy in the supernode data and unseal the crypto keys */
    memcpy(&_super, super, sizeof(supernode_t));
    crypto_ctx = &_super.crypto_ctx;

    crypto_ekey_t * skey
        = derive_skey2(__enclave_key__, &_super.root_dnode, &_super.uuid);
    if (skey == NULL) {
        return -1;
    }

    if (super_op == SUPERNODE_DECRYPT) {
        enclave_crypto_ekey(&crypto_ctx->ekey, skey, UC_DECRYPT);
        enclave_crypto_ekey(&crypto_ctx->mkey, skey, UC_DECRYPT);
    }

    if (supernode_hash(&_super, crypto_ctx, &crypto_ctx->mac, super_op)) {
        goto out;
    }

    /* only copy out data, if we are encrypting */
    if (super_op == SUPERNODE_ENCRYPT) {
        enclave_crypto_ekey(&crypto_ctx->ekey, skey, UC_ENCRYPT);
        enclave_crypto_ekey(&crypto_ctx->mkey, skey, UC_ENCRYPT);
        memcpy(super, &_super, sizeof(supernode_t));
    }

    ret = 0;
out:
    free(skey);
    return ret;
}

static int
usgx_supernode_mount(supernode_t * super)
{
    int err = -1, i = 0, ret, len, uname_len;
    crypto_mac_t mac;
    crypto_context_t _ctx, *crypto_ctx = &_ctx;
    snode_user_t * curr_user;
    snode_entry_t * snode_entry;

    /* derive the sealing key */
    crypto_ekey_t * skey
        = derive_skey2(__enclave_key__, &super->root_dnode, &super->uuid);
    if (skey == NULL) {
        return -1;
    }

    memcpy(crypto_ctx, &super->crypto_ctx, sizeof(crypto_context_t));
    enclave_crypto_ekey(&crypto_ctx->ekey, skey, UC_DECRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, skey, UC_DECRYPT);

    /* 1 - verify that the supernode matches */
    err = supernode_hash(super, crypto_ctx, &mac, SUPERNODE_DECRYPT);
    if (err) {
        goto out;
    }

    /* 2 - if the user owns this public key, lets skip all this */
    err = memcmp(super->owner_pubkey, user_supernode.owner_pubkey,
                 sizeof(pubkey_t));
    if (err == 0) {
        goto out;
    }

    err = E_ERROR_NOTFOUND;

    /* 2 - check the hash value */
    curr_user = (snode_user_t *)super->users_buffer;
    while (i < super->user_count) {
        uname_len = curr_user->len;
        len = sizeof(snode_user_t) + curr_user->len;

        if (memcmp(&curr_user->pubkey_hash, user_pubkey, sizeof(pubkey_t))) {
            goto next_entry;
        }

        /* add the supernode to the map of supernodes */
        snode_entry
            = (snode_entry_t *)malloc(sizeof(snode_entry_t) + uname_len + 1);
        memcpy(&snode_entry->super, super, sizeof(supernode_t));

        /* add the username */
        snode_entry->len = uname_len;
        memcpy(snode_entry->username, curr_user->username, uname_len);
        snode_entry->username[uname_len] = '\0';

        /* add the entry and exit */
        SLIST_INSERT_HEAD(snode_list, snode_entry, next_entry);
        err = 0;
        goto out;

    next_entry:
        curr_user = (snode_user_t *)(((uint8_t *)curr_user) + len);
        i++;
    }

out:
    free(skey);
    return err;
}

/**
 * Verifies if you have access rights to the supernode been mounted
 * @param super is the supernode object
 * @return 0 on success
 */
int
ecall_supernode_mount(supernode_t * super)
{
    return usgx_supernode_mount(super);
}

/**
 * Checks if the following user has the right to access the file
 *
 * @param dnode_head
 * @param rights
 * @return 0 if one has access to the file
 */
static int
usgx_check_rights(dirnode_header_t * dnode_head,
                  acl_list_head_t * acl_list,
                  acl_rights_t rights)
{
    int ret = -1;
    snode_entry_t * snode_entry;
    acl_list_entry_t * acl_entry;
    acl_data_t * acl_data;
    supernode_t * super;

    /* 1 - checks if the user owns the folder */
    ret = memcmp(&dnode_head->root, &user_supernode.root_dnode,
                 sizeof(shadow_t));
    if (ret == 0) {
        goto done;
    }

    /* 2 - Find the supernode this believes it */
    SLIST_FOREACH(snode_entry, snode_list, next_entry)
    {
        super = &snode_entry->super;
        if (memcmp(&dnode_head->root, &super->root_dnode, sizeof(shadow_t))) {
            continue;
        }

        // if we are here, the current user is the owner
        goto check;
    }

    /* we could not find a user in the supernode list */
    goto out;

check:
    /* go through the list of all the dnode acl entries */
    SIMPLEQ_FOREACH(acl_entry, acl_list, next_entry)
    {
        acl_data = &acl_entry->acl_data;
        if (strncmp(snode_entry->username, acl_data->name, snode_entry->len)) {
            continue;
        }

        // check if the rights match
        ret = (rights & acl_data->rights) == rights;
        if (ret) {
            ret = 0;
        }
        goto out;
    }

    goto out;

done:
    ret = 0;

out:
    return ret;
}

int
ecall_check_rights(dirnode_header_t * dnode_head,
                   acl_list_head_t * acl_list,
                   acl_rights_t rights)
{
    return usgx_check_rights(dnode_head, acl_list, rights);
}
