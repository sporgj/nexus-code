#include <uuid/uuid.h>

#include "nexus_untrusted.h"

void
nexus_uuid(struct uuid * uuid)
{
    uuid_generate((uint8_t *)uuid);
}

static int
read_file(const char * fpath, uint8_t ** p_buffer, size_t * p_size)
{
    int       ret    = -1;
    ssize_t   size   = 0;
    ssize_t   nbytes = 0;
    uint8_t * buffer = NULL;
    FILE *    fd     = NULL;

    fd = fopen(fpath, "rb");
    if (fd == NULL) {
        log_error("fopen(%s) FAILED", fpath);
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    if (size == -1) {
        log_error("ftell returned -1");
        goto out;
    }
    fseek(fd, 0, SEEK_SET);

    buffer = (uint8_t *)calloc(1, size);
    if (buffer == NULL) {
        log_error("allocation error (bytes=%zu)", size);
        goto out;
    }

    nbytes = fread(buffer, 1, size, fd);
    if (nbytes != size) {
        log_error("fread FAILED. tried=%zu, got=%zu", size, nbytes);
        goto out;
    }

    *p_buffer = buffer;
    *p_size   = size;

    ret = 0;
out:
    fclose(fd);

    if (ret) {
        nexus_free2(buffer);
    }

    return ret;
}

static int
write_file(const char * fpath, uint8_t * buffer, size_t size)
{
    int    ret    = -1;
    size_t nbytes = 0;
    FILE * fd     = NULL;

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
        log_error("fopen(%s) FAILED", fpath);
        return -1;
    }

    nbytes = fwrite(buffer, 1, size, fd);
    if (nbytes != size) {
        log_error("fwrite FAILED. tried=%zu, got=%zu", size, nbytes);
        goto out;
    }

    ret = 0;
out:
    fclose(fd);
    return ret;
}

int
write_volume_metadata_files(struct supernode * supernode,
                            struct dirnode *   root_dirnode,
                            struct volumekey * volkey,
                            const char *       metadata_path,
                            const char *       volumekey_fpath)
{
    int    ret             = -1;
    size_t size            = 0;
    char * dirnode_fname   = metaname_bin2str(&root_dirnode->header.uuid);
    char * supernode_fpath = strndup(metadata_path, PATH_MAX);
    char * dirnode_fpath   = strndup(metadata_path, PATH_MAX);

    supernode_fpath = pathjoin(supernode_fpath, NEXUS_FS_SUPERNODE_NAME);
    dirnode_fpath = pathjoin(dirnode_fpath, dirnode_fname);

    // write out the files now
    size = supernode->header.total_size;
    log_debug("Writing supernode [%zu bytes]: %s", size, supernode_fpath);
    if (write_file(supernode_fpath, (uint8_t *)supernode, size)) {
        goto out;
    }

    size = root_dirnode->header.total_size;
    log_debug("Writing dirnode [%zu bytes]: %s", size, dirnode_fpath);
    if (write_file(dirnode_fpath, (uint8_t *)root_dirnode, size)) {
        goto out;
    }

    size = sizeof(struct volumekey);
    log_debug("Writing volumekey [%zu bytes]: %s", size, volumekey_fpath);
    if (write_file(volumekey_fpath, (uint8_t *)volkey, size)) {
        goto out;
    }

    ret = 0;
out:
    nexus_free2(dirnode_fname);
    nexus_free2(dirnode_fpath);
    nexus_free2(supernode_fpath);

    return ret;
}

int
read_volume_metadata_files(const char *        metadata_path,
                           const char *        volumekey_fpath,
                           struct supernode ** p_supernode,
                           struct volumekey ** p_volumekey)
{
    int                ret       = -1;
    size_t             size      = 0;
    struct supernode * supernode = NULL;
    struct volumekey * volumekey = NULL;

    char * supernode_fpath = strndup(metadata_path, PATH_MAX);
    supernode_fpath = pathjoin(supernode_fpath, NEXUS_FS_SUPERNODE_NAME);

    ret = read_file(supernode_fpath, (uint8_t **)&supernode, &size);
    if (ret != 0) {
        log_error("reading supernode(%s) FAILED", supernode_fpath);
        goto out;
    }

    ret = read_file(volumekey_fpath, (uint8_t **)&volumekey, &size);
    if (ret != 0) {
        log_error("reading volumekey(%s) FAILED", volumekey_fpath);
        goto out;
    }

    *p_supernode = supernode;
    *p_volumekey = volumekey;

    ret = 0;
out:
    nexus_free2(supernode_fpath);

    if (ret) {
        nexus_free2(supernode);
        nexus_free2(volumekey);
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
