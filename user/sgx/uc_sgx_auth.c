#include "enclave_private.h"

#include <mbedtls/pk.h>

#define RSA_PUB_DER_MAX_BYTES 38 + 2 * MBEDTLS_MPI_MAX_SIZE

static void
init_supernode(supernode_t * super, uint8_t * buf, int len)
{
    crypto_context_t _ctx, *crypto_ctx = &_ctx;
    mbedtls_md_context_t _h, *hmac_ctx = &_h;
    super->count = 0;

    sgx_read_rand((uint8_t *)crypto_ctx, sizeof(crypto_context_t));

    mbedtls_md_init(hmac_ctx);
    mbedtls_md_setup(hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(hmac_ctx, (uint8_t *)&crypto_ctx->mkey,
                           CRYPTO_MAC_KEY_SIZE);

    mbedtls_md_hmac_update(hmac_ctx, (uint8_t *)&super->root_dnode,
                           sizeof(shadow_t));
    mbedtls_md_hmac_update(hmac_ctx, buf, len);

    mbedtls_md_hmac_finish(hmac_ctx, (uint8_t *)&crypto_ctx->mac);
    mbedtsl_md_free(hmac_ctx);

    enclave_crypto_ekey(&crypto_ctx->ekey, UC_ENCRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_ENCRYPT);
}

int
ecall_initialize(supernode_t * super, mbedtls_pk_context * rsa)
{
    int err = -1, len;
    supernode_t _super;

    /* sizeof(buffer) = sizeof(exponent) + sizeof(modulus) + tag */
    unsigned char buf[RSA_PUB_DER_MAX_BYTES];

    if ((len = mbedtls_pk_write_pubkey_der(rsa, buf, sizeof(buf))) < 0) {
        err = E_ERROR_CRYPTO;
        goto out;
    }

    memcpy(&_super.root_dnode, &super->root_dnode, sizeof(shadow_t));

    init_supernode(&_super, buf, len);

    memcpy(super, &_super, sizeof(supernode_t));

    err = 0;
out:
    return err;
}
