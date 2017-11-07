#include "nexus_untrusted.h"

int
util_generate_signature(mbedtls_pk_context * pk,
                        uint8_t *            data,
                        size_t               len,
                        uint8_t **           signature,
                        size_t *             signature_len)
{
    int                      ret = -1;
    int                      err = -1;
    uint8_t                  hash[CONFIG_HASH_BYTES];
    uint8_t *                buf = NULL;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context  entropy;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    err = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (err) {
        log_error("mbedtls_ctr_drbg_seed failed ret=%#x", err);
        goto out;
    }

    buf = (uint8_t *) calloc(1, MBEDTLS_MPI_MAX_SIZE);
    if (buf == NULL) {
	log_error("allocation error");
	goto out;
    }

    mbedtls_sha256(data, len, hash, 0);

    err = mbedtls_pk_sign(pk,
                          MBEDTLS_MD_SHA256,
                          hash,
                          0,
                          buf,
                          signature_len,
                          mbedtls_ctr_drbg_random,
                          &ctr_drbg);
    if (err) {
        log_error("mbedtls_pk_sign ret = %d", err);
        goto out;
    }

    *signature = buf;

    ret = 0;
out:
    if (ret && buf) {
	nexus_free(buf);
    }

    return ret;
}
