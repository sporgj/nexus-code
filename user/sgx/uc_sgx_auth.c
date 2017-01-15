#include "enclave_private.h"

#include <mbedtls/pk.h>

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE

bool enclave_is_logged_in = false;

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

// TODO add code to verify enclave
int
ecall_ucafs_login(supernode_t * super, mbedtls_pk_context * pk_ctx)
{
    int err = -1, len;
    supernode_t _super;
    crypto_context_t *crypto_ctx = &_super.crypto_ctx,
                     *crypto_ctx1 = &super->crypto_ctx;
    unsigned char buf[RSA_PUB_DER_MAX_BYTES], *c;

    if ((len = mbedtls_pk_write_pubkey_der(pk_ctx, buf, sizeof(buf))) < 0) {
        err = E_ERROR_CRYPTO;
        goto out;
    }

    c = buf + sizeof(buf) - len - 1;

    memcpy(&_super, super, sizeof(supernode_t));

    enclave_crypto_ekey(&crypto_ctx->ekey, UC_DECRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_DECRYPT);

    supernode_hash(&_super, c, len, &crypto_ctx->mac);
    if (memcmp(&crypto_ctx->mac, &crypto_ctx1->mac, sizeof(crypto_mac_t))) {
        err = E_ERROR_LOGIN;
        goto out;
    }

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
