#include "enclave_private.h"

#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE

bool enclave_is_logged_in = false;

/* the enclave private key */
static const char enclave_private_key[]
    = "-----BEGIN RSA PRIVATE KEY-----"
      "MIIEogIBAAKCAQEAiQd8wyQpBqqRyCiYrulBagPW8xSrrsDBO5fyZ0G8UQU3pVL1"
      "v3frHfpNSoGPuK7MvPDvCyldzHUUeFBd6IiD9zbnsuZuwx7+BCbNzmiebXFr+EYt"
      "5f/ngyIEE1/NzilM35gT9ehej4tAzocjEKweuSTsX3Xh0X9NMNpgLSVKBrf/Fx1O"
      "PMLJ8GJoFsYVEcVFvN6KEQOfwBMq0qOYmGT5z9cYyipsu+K9lTnFefgxqL3zI0u1"
      "IRWO/kh3DSVGXsB5WcKl6F8N9u5m2+yC3HMf94pWJtyxTkKl5smxpUydxRGTy8Ba"
      "rH6YxIbv7l98f9YSh9aaSZ7ak2EwqsaBSbZDQwIDAQABAoIBAEPoyQTww8BBAhR/"
      "QgPVJ40BsCIxyU/GyTzedcyEgG5qtoQhVBb6uDPYGzvkb7SoNGEiymTusESmdWmW"
      "8qNOHJCEzlkT6CqdDmhCTtaPdIxqnIajSRXmN/b+AaUUYqtcPnPFK4dADLT43zo7"
      "ML6Pfn5k9RvuEObBPyEJ6IYXJ9Oh3Eq4SZ1k41lMFIP49S6WG/BsifHCHFsLyyZ5"
      "rER69LzgdXPlq8YZ9Dgzdz+wO5DCtL38FG6yOYa0dcd9vbjvLUHfAOUaqfyEqtCF"
      "ZWTQON4LBi6jf6PmUk5PoGFXKBDUoefkVZVVGW090PdxaQsYjqUXQVSwI4l8rA/D"
      "23BFG5ECgYEAxYhVJsEEjGpr3Boyyc4Qx7oeKn+j6NkKTKMcQPq7pgS6LAIDlAOy"
      "V6Y+IYXC+xsZOY5YYifK/Nn9WOIEPjrLRP+zHv5C9Dsnx0UOTBm6foBPGKssp1et"
      "lqY1DKzbSMDGMBbKR3LAvzMec3/R7Up3pALwWg1lhy/+TXZ0kbymUpkCgYEAsZag"
      "tcGa+GeI/P+hPnOwP2BEj0iDGI82SFSlgDkJsO26sFLv8271mot1kFWaJfAkkzz/"
      "GLg2UfmOp6+3WRllj6YYrgxAEMEjbHMG3rmIp8j4ATpRFQK6j4LmhHEQmc2gkIsl"
      "LqJKibJkePQug6Q9jtCFMD466odhvYRazSkpSjsCgYBgb1V67QKGdrIfq16eLQ7+"
      "Ivv1LYlc9RDVJ1B03LPdsjMdpwIOMdvQdKWiggYVxz4CXl8B1IGB/f50dSszIkr4"
      "bYkKGYGgcHzUCP+Y4XqtpYB3/6F2NRTXFl+Rx5Xqp8pZ0daBGSHGdnNoWb+oBBHy"
      "rUif/ihR3nldYfY47AubCQKBgEswn3LVOiwaiiG0iizLBsCOnficlwT6/dy6Giij"
      "/bpvrS+irf2/6TU5/tjRpaaSeqnslYV92WHz67aL63FKE3oytRhcD3QIklsEiNAc"
      "dgO0T20Vp+bhdOP2ZGuHA6RbL7SDdYa9KBoM8gVUPa13CKlDGGFIt+E82OFI/LkI"
      "yHapAoGAdwOHLw6MetIKzatttNtvw+o9aDcIEdicJjHZ8Fnv3OtS6WgpkLc6eWdu"
      "ixrQmyrz8ehhXDDOFWsplaL5i9R+PVCuukE+7sVVCZhj3QclE99ejtN172uKtt7b"
      "yxVvR8Xb4Au5JueXU+QkoIMjCUgYAb+6gd3qbEfIl5JLFXJEtg4="
      "-----END RSA PRIVATE KEY-----";

static const size_t enclave_private_key_len = sizeof(enclave_private_key);

enum auth_stage { CHALLENGE, RESPONSE, COMPLETE };

enum auth_stage auth_stage = CHALLENGE;

static void
supernode_hash(supernode_t * super, uint8_t * buf, int len, crypto_mac_t * mac)
{
    crypto_context_t * crypto_ctx = &super->crypto_ctx;
    mbedtls_md_context_t _h, *hmac_ctx = &_h;

    mbedtls_md_init(hmac_ctx);
    mbedtls_md_setup(hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                           CRYPTO_MAC_KEY_SIZE);

    mbedtls_md_hmac_update(hmac_ctx, (uint8_t *)&super->root_dnode,
                           sizeof(shadow_t));
    mbedtls_md_hmac_update(hmac_ctx, buf, len);

    mbedtls_md_hmac_finish(hmac_ctx, (uint8_t *)mac);
    mbedtls_md_free(hmac_ctx);
}

static void
init_supernode(supernode_t * super, uint8_t * buf, int len)
{
    crypto_context_t * crypto_ctx = &super->crypto_ctx;
    mbedtls_md_context_t _h, *hmac_ctx = &_h;
    super->count = 0;

    sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));

    supernode_hash(super, buf, len, &crypto_ctx->mac);

    enclave_crypto_ekey(&crypto_ctx->ekey, UC_ENCRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_ENCRYPT);
}

int
ecall_initialize(supernode_t * super, mbedtls_pk_context * pk_ctx)
{
    int err = -1, len;
    supernode_t _super;

    /* sizeof(buffer) = sizeof(exponent) + sizeof(modulus) + tag */
    unsigned char buf[RSA_PUB_DER_MAX_BYTES], *c;

    if ((len = mbedtls_pk_write_pubkey_der(pk_ctx, buf, sizeof(buf))) < 0) {
        err = E_ERROR_CRYPTO;
        goto out;
    }

    c = buf + sizeof(buf) - len - 1;

    memcpy(&_super.root_dnode, &super->root_dnode, sizeof(shadow_t));

    init_supernode(&_super, c, len);

    memcpy(super, &_super, sizeof(supernode_t));

    err = 0;
out:
    return err;
}

static int
custom_drbg(void * out, unsigned char * seed, size_t len, size_t * olen)
{
    sgx_read_rand(out, len);
    *olen = len;

    return 0;
}

uint8_t auth_hash[32];

/**
 * Generates the "challenge" portion of the test.
 */
int
ecall_ucafs_challenge(uint8_t nonce_a[32], struct enclave_auth * auth)
{
    int err = -1;
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

    /* compute the hash of the nonce and our measurement */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, nonce_a, sizeof(nonce_a));
    mbedtls_sha256_update(&sha256_ctx, (uint8_t *)&enclave_auth_data,
                          sizeof(struct enclave_auth_data));
    mbedtls_sha256_finish(&sha256_ctx, auth_hash);
    mbedtls_sha256_free(&sha256_ctx);

    /* sign the structure and return */
    if (mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, auth_hash, 0, auth->signature,
                        &auth->sig_len, mbedtls_ctr_drbg_random, &ctr_drbg)) {
        goto out;
    }

    memcpy(auth, &enclave_auth_data, sizeof(enclave_auth_data));
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
    crypto_context_t _ctx, * crypto_ctx = &_ctx;
    crypto_mac_t mac;
    unsigned char buf[RSA_PUB_DER_MAX_BYTES], *c;

    if (auth_stage != RESPONSE) {
        return -1;
    }

    /* 1 - Verify the public key matches the private key */
    if (mbedtls_pk_verify(user_pubkey_ctx, MBEDTLS_MD_SHA256, auth_hash, 0,
                          user_signature, sig_len)) {
        goto out;
    }

    /* 2 - Verify the supernode has not been tampered and was created with the
     * specified public key */
    len = mbedtls_pk_write_pubkey_der(user_pubkey_ctx, buf, sizeof(buf));
    if (len < 0) {
        err = E_ERROR_CRYPTO;
        goto out;
    }

    c = buf + sizeof(buf) - len - 1;

    memcpy(crypto_ctx, &super->crypto_ctx, sizeof(crypto_context_t));
    enclave_crypto_ekey(&crypto_ctx->ekey, UC_DECRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_DECRYPT);

    supernode_hash(super, c, len, &mac);
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
