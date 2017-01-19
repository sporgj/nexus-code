#include "enclave_private.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE

bool enclave_is_logged_in = false;

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

static int
supernode_hash(supernode_t * super,
               mbedtls_pk_context * user_pubkey_ctx,
               crypto_context_t * crypto_ctx,
               crypto_mac_t * mac,
               snode_crypto_t op)
{
    int len, bytes_left;
    crypto_iv_t iv;
    size_t off;
    mbedtls_md_context_t _h, *hmac_ctx = &_h;
    mbedtls_aes_context _a, *aes_ctx = &_a;
    uint8_t buf[RSA_PUB_DER_MAX_BYTES] = {0}, *c, stream_block[16];

    len = mbedtls_pk_write_pubkey_der(user_pubkey_ctx, buf, sizeof(buf));
    if (len < 0) {
        return E_ERROR_CRYPTO;
    }

    c = buf + sizeof(buf) - len - 1;

    /* generate the hmac */
    mbedtls_md_init(hmac_ctx);
    mbedtls_md_setup(hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                           CRYPTO_MAC_KEY_SIZE);

    mbedtls_md_hmac_update(hmac_ctx, (uint8_t *)super,
                           sizeof(supernode_payload_t));
    mbedtls_md_hmac_update(hmac_ctx, c, len);
    
    // lets go through every user
    mbedtls_aes_init(aes_ctx);
    mbedtls_aes_setkey_enc(aes_ctx, (uint8_t *)&crypto_ctx->ekey, CRYPTO_AES_KEY_SIZE_BITS);

    if (op) {
        sgx_read_rand((uint8_t *)&crypto_ctx->iv, sizeof(crypto_iv_t));
    }

    memcpy(&iv, &crypto_ctx->iv, sizeof(crypto_iv_t));

    bytes_left = super->users_buflen;
    while (bytes_left > 0) {
        // lets reuse buf
        len = MIN(sizeof(buf), bytes_left);
        memcpy(buf, super->users, len);

        if (op == SUPERNODE_ENCRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, len, &off, iv.bytes, stream_block, buf, buf);
        }

        mbedtls_md_hmac_update(hmac_ctx, buf, len);

        if (op == SUPERNODE_ENCRYPT) {
            mbedtls_aes_crypt_ctr(aes_ctx, len, &off, iv.bytes, stream_block, buf, buf);
        }

        memcpy(super->users, buf, len);

        bytes_left -= len;
    }

    mbedtls_md_hmac_finish(hmac_ctx, (uint8_t *)mac);
    mbedtls_md_free(hmac_ctx);

    return 0;
}

int
ecall_initialize(supernode_t * super, mbedtls_pk_context * pk_ctx)
{
    int err = -1, len;
    supernode_t _super;
    crypto_context_t * crypto_ctx = &_super.crypto_ctx;

    /* initialize the data */
    memcpy(&_super.root_dnode, &super->root_dnode, sizeof(shadow_t));
    _super.count = 0;
    _super.users_buflen = 0;
    sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));

    /* hash it */
    if (supernode_hash(&_super, pk_ctx, crypto_ctx, &crypto_ctx->mac,
                       SUPERNODE_ENCRYPT)) {
        return E_ERROR_CRYPTO;
    }

    enclave_crypto_ekey(&crypto_ctx->ekey, UC_ENCRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_ENCRYPT);

    memcpy(super, &_super, sizeof(supernode_t));

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

int
ecall_ucafs_response(supernode_t * super,
                     mbedtls_pk_context * user_pubkey_ctx,
                     uint8_t * user_signature,
                     size_t sig_len)
{
    int err = -1, len;
    crypto_context_t _ctx, *crypto_ctx = &_ctx;
    crypto_mac_t mac;
    unsigned char buf[RSA_PUB_DER_MAX_BYTES], *c;

    if (auth_stage != RESPONSE || sig_len > MBEDTLS_MPI_MAX_SIZE) {
        return -1;
    }

    /* 1 - Verify the public key matches the private key */
    if (mbedtls_pk_verify(user_pubkey_ctx, MBEDTLS_MD_SHA256, na_hash, 0,
                          user_signature, sig_len)) {
        goto out;
    }

    /* 2 - Verify the supernode has not been tampered and was created with the
     * specified public key */
    memcpy(crypto_ctx, &super->crypto_ctx, sizeof(crypto_context_t));
    enclave_crypto_ekey(&crypto_ctx->ekey, UC_DECRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_DECRYPT);

    supernode_hash(super, user_pubkey_ctx, crypto_ctx, &mac, SUPERNODE_NONE);
    if (memcmp(&crypto_ctx->mac, &mac, sizeof(crypto_mac_t))) {
        err = E_ERROR_LOGIN;
        goto out;
    }

    auth_stage = COMPLETE;
    enclave_is_logged_in = true;

    err = 0;
out:
    return err;
}

// TODO
int
ecall_seal_supernode(supernode_t * super)
{
    int err = -1;

    err = 0;
out:
    return err;
}
