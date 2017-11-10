#include <uuid/uuid.h>

#include "nexus_untrusted.h"

void
nexus_uuid(struct uuid * uuid)
{
    uuid_generate((uint8_t *)uuid);
}

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

char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max)
{
    size_t len1 = strnlen(dest, max);
    size_t len2 = (join == NULL) ? 0 : strnlen(join, max);
    size_t len3 = strnlen(src, max);
    size_t total = len1 + len2 + len3;

    if (total > max) {
        // XXX should we report here??
        return NULL;
    }

    char * result = realloc(dest, total + 1);
    if (result == NULL) {
        log_error("allocation error");
        return NULL;
    }

    if (join != NULL) {
        memcpy(result + len1, join, len2);
    }

    memcpy(result + len1 + len2, src, len3);
    result[total] = '\0';

    return result;
}

char *
my_strncat(char * dest, const char * src, size_t max)
{
    return my_strnjoin(dest, NULL, src, max);
}

char *
pathjoin(char * directory, const char * filename)
{
    return my_strnjoin(directory, "/", filename, PATH_MAX);
}
