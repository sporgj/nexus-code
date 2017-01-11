#include "enclave_private.h"

#include <mbedtls/pk.h>

int
ecall_new_ucafs_repo(supernode_t * super, mbedtls_rsa_context * rsa)
{
    int err = -1, len;
    mbedtls_md_context_t hmac_ctx;
    supernode_t _super;
    crypto_context_t _ctx, * crypto_ctx = &_ctx;

    /* sizeof(buffer) = sizeof(exponent) + sizeof(modulus) + tag */
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE * 2 + 20], *c = buf + sizeof(buf);

    if ((len = mbedtls_pk_write_pubkey_der(rsa, &c, buf)) < 0) {
	err = E_ERROR_CRYPTO;
	goto out;
    }

    /* compute the sha256 */
    mbedtls_sha256(buf, len, &super->pubkey, 0);

    /* now sign the whole bunch and call it a day */
    sgx_read_rand(crypto_ctx, sizeof(crypto_context_t));
    mbedtls_md_init(&hmac_ctx);
    mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                     1);

    mbedtls_md_hmac_starts(&hmac_ctx, (uint8_t *)&crypt_ctx->mkey, CRYPTO_MAC_KEY_SIZE);

    mbedtls_md_hmac_update(&hmac_ctx, &super->root_dnode);
    mbedtls_md_hmac_update(&hmac_ctx, &super->pubkey);

    mbedtls_md_hmac_finish(&hmac_ctx, (uint8_t *)&crypto_ctx->mac);
    mbedtls_md_free(&hmac_ctx);

    enclave_crypto_ekey(&crypto_ctx->ekey, UC_ENCRYPT);
    enclave_crypto_ekey(&crypto_ctx->mkey, UC_ENCRYPT);

    memcpy(&super->crypto_ctx, crypto_ctx, sizeof(crypto_context_t));

    err = 0;
out:
    return err;
}
