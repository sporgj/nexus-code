#include <sgx_report.h>
#include <sgx_tkey_exchange.h>
#include <sgx_trts.h>

#include "../enclave_internal.h"


struct ecdh_public_key           global_owner_pubkey;

struct ecdh_secret_key           global_owner_privkey;


// FIXME: the usage of this function should be reconsidered
static int
__copy_to_untrusted(void * trusted_ptr, int len, uint8_t ** untrusted_ptr)
{
    int       err       = -1;
    uint8_t * ocall_ptr = NULL;

    err = ocall_calloc((void **)&ocall_ptr, len);

    if (err || ocall_ptr == NULL) {
        log_error("allocation failed. err=%x, untrusted_ptr=%p\n", err, ocall_ptr);
        return -1;
    }

    memcpy(ocall_ptr, trusted_ptr, len);

    *untrusted_ptr = ocall_ptr;

    return 0;
}

// FIXME
static void
__copy_from_untrusted(void * untrusted_ptr, int len, uint8_t ** trusted_ptr)
{
    uint8_t * _result = nexus_malloc(len);

    memcpy(_result, untrusted_ptr, len);

    *trusted_ptr = _result;
}


static int
create_quote_from_pubkey(struct ecdh_public_key       * pubkey,
                         const sgx_target_info_t * qe_tgt_info,
                         sgx_report_t            * report)
{
    sgx_report_data_t report_data = { 0 };

    // hash the public key into the report data (64 bytes)
    // XXX: the ECC public key is actually 64 bytes, I add this extra step for demonstration
    crypto_hash_sha512((uint8_t *)&report_data.d, pubkey->bytes, sizeof(struct ecdh_public_key));

    {
        int ret = sgx_create_report(qe_tgt_info, &report_data, report);

        if (ret != SGX_SUCCESS) {
            log_error("Error creating report (ret=%x)\n", ret);
            return -1;
        }
    }

    return 0;
}

static int
validate_quote_and_copy_pubkey(sgx_quote_t * quote, struct ecdh_public_key * quote_pubkey)
{
    sgx_report_body_t * owner_body = NULL;
    sgx_report_body_t * other_body = NULL;

    sgx_report_t        owner_report;

    int ret = -1;


    /* verify the mr measurement */
    ret = sgx_create_report(NULL, NULL, &owner_report);
    if (ret != 0) {
        log_error("sgx_create_report FAILED ret=%x\n", ret);
        return -1;
    }

    owner_body = &owner_report.body;
    other_body = &quote->report_body;


    /* check the quote provenance */
    if (memcmp(&owner_body->mr_enclave, &other_body->mr_enclave, sizeof(sgx_measurement_t))
            || memcmp(&owner_body->mr_signer, &other_body->mr_signer, sizeof(sgx_measurement_t))) {
        log_error("enclave provenance check failed\n");
        return -1;
    }


    /* verify the other's public key */
    {
        uint8_t hash[crypto_hash_BYTES];

        crypto_hash_sha512(hash, quote_pubkey->bytes, sizeof(struct ecdh_public_key));

        if (memcmp(hash, other_body->report_data.d, sizeof(hash))) {
            log_error("could not validate hash public key\n");
            return -1;
        }
    }

    return 0;
}


int
ecall_new_instance(const sgx_target_info_t  * target_info_IN,
                   sgx_report_t             * report_out,
                   struct ecdh_public_key   * pubkey_out,
                   uint8_t                 ** sealed_privkey_out,
                   size_t                   * sealed_privkey_len_out)
{
    if (crypto_box_keypair(global_owner_pubkey.bytes, global_owner_privkey.bytes)) {
        log_error("crypto_box_keypair() FAILED\n");
        return -1;
    }

    if (create_quote_from_pubkey(&global_owner_pubkey, target_info_IN, report_out)) {
        log_error("create_quote() FAILED\n");
        return -1;
    }

    // seal the private key and send it out
    {
        uint8_t * result = NULL;

        result = crypto_seal_data(
                     global_owner_privkey.bytes, sizeof(struct ecdh_secret_key), sealed_privkey_len_out);

        if (result == NULL) {
            log_error("sealing private key FAILED\n");
            return -1;
        }

        if (__copy_to_untrusted(result, *sealed_privkey_len_out, sealed_privkey_out)) {
            nexus_free(result);
            log_error("could not copy out private key\n");
            return -1;
        }

        nexus_free(result);
    }

    // copy out the public key
    memcpy(pubkey_out->bytes, global_owner_pubkey.bytes, sizeof(struct ecdh_public_key));

    return 0;
}

int
ecall_mount_instance(struct ecdh_public_key * pubkey_IN,
                     uint8_t                * sealed_privkey_in,
                     size_t                   sealed_privkey_len)
{
    uint8_t * result          = NULL;
    size_t    unsealed_size   = 0;
    uint8_t * _sealed_privkey = NULL;


    // copy in the sealed key
    __copy_from_untrusted(sealed_privkey_in, sealed_privkey_len, &_sealed_privkey);

    result = crypto_unseal_data(_sealed_privkey, sealed_privkey_len, &unsealed_size);

    nexus_free(_sealed_privkey);

    if (result == NULL) {
        log_error("unsealing private key FAILED\n");
        return -1;
    }

    memcpy(global_owner_pubkey.bytes, pubkey_IN->bytes, sizeof(struct ecdh_public_key));
    memcpy(global_owner_privkey.bytes, result, sizeof(struct ecdh_secret_key));

    // TODO check for keypair compatibility

    nexus_free(result);

    return 0;
}

int
ecall_exchange_rootkey(sgx_quote_t             * other_quote_in,
                       struct ecdh_public_key  * other_pubkey_IN,
                       struct ecdh_public_key  * ephemeral_pk_out,
                       struct ecdh_nonce       * nonce_out,
                       uint8_t                ** wrapped_secret_out,
                       int                     * wrapped_secret_len_out)
{
    uint8_t * result     = NULL;

    int       result_len = 0;

    struct ecdh_nonce random_nonce = { 0 };

    struct ecdh_public_key pk_eph;
    struct ecdh_secret_key sk_eph;


    if (global_volumekey == NULL) {
        log_error("no available volume key\n");
        return -1;
    }


    if (validate_quote_and_copy_pubkey(other_quote_in, other_pubkey_IN)) {
        log_error("could not validate quote/pubkey\n");
        return -1;
    }


    // generate the ephermeral keypair
    if (crypto_box_keypair(pk_eph.bytes, sk_eph.bytes)) {
        log_error("crypto_box_keypair() FAILED\n");
        return -1;
    }

    crypto_randombytes(&random_nonce, sizeof(struct ecdh_nonce));

    result = crypto_ecdh_encrypt(other_pubkey_IN,
                                 &sk_eph,
                                 global_volumekey->key,
                                 nexus_key_bytes(global_volumekey),
                                 &result_len,
                                 &random_nonce);

    if (result == NULL) {
        log_error("could not wrap secret\n");
        return -1;
    }


    // copy out the nonce and the wrapped secret
    memcpy(ephemeral_pk_out->bytes, pk_eph.bytes, sizeof(struct ecdh_public_key));
    memcpy(nonce_out, &random_nonce, sizeof(struct ecdh_nonce));

    if (__copy_to_untrusted(result, result_len, wrapped_secret_out)) {
        log_error("could not copy data out\n");
        goto err;
    }

    *wrapped_secret_len_out = result_len;


    nexus_free(result);
    return 0;
err:
    nexus_free(result);
    return -1;
}

static int
__seal_rootkey_and_export(uint8_t                 * unwrapped_buffer,
                          size_t                    unwrapped_buflen,
                          struct nexus_key_buffer * sealed_volkey_keybuf_out)
{
    struct nexus_key_buffer * key_buffer = NULL;

    struct nexus_key other_vol_rootkey;

    nexus_init_key(&other_vol_rootkey, VOLUMEKEY_KEY_TYPE);

    if (__nexus_key_from_buf(&other_vol_rootkey,
                VOLUMEKEY_KEY_TYPE,
                unwrapped_buffer,
                unwrapped_buflen)) {
        log_error("could not create rootkey buffer\n");
        return -1;
    }

    key_buffer = key_buffer_seal(&other_vol_rootkey);

    nexus_free_key(&other_vol_rootkey);

    key_buffer_copy(key_buffer, sealed_volkey_keybuf_out);

    key_buffer_free(key_buffer);

    return 0;
}

int
ecall_extract_rootkey(struct ecdh_public_key  * ephemeral_pk_IN,
                      uint8_t                 * wrapped_secret_in,
                      size_t                    wrapped_secret_len,
                      struct ecdh_nonce       * nonce_IN,
                      struct nexus_key_buffer * sealed_volkey_keybuf_out)
{
    uint8_t * result     = NULL;

    int       result_len = 0;
    int       offset     = 0;

    uint8_t * unwrapped_buffer = NULL;
    size_t    unwrapped_buflen = 0;

    uint8_t * wrapped_secret_copy = NULL;


    __copy_from_untrusted(wrapped_secret_in, wrapped_secret_len, &wrapped_secret_copy);

    result = crypto_ecdh_decrypt(ephemeral_pk_IN,
                                 &global_owner_privkey,
                                 wrapped_secret_copy,
                                 wrapped_secret_len,
                                 &result_len,
                                 &offset,
                                 nonce_IN);

    nexus_free(wrapped_secret_copy);

    if (result == NULL) {
        log_error("could not wrap secret\n");
        return -1;
    }

    unwrapped_buffer = result + offset;
    unwrapped_buflen = result_len;


    if (result_len != VOLUMEKEY_SIZE_BYTES) {
        log_error("Incorrect sizeof unwrapped rootkey: expected=%d, got=%d\n",
                  VOLUMEKEY_SIZE_BYTES,
                  result_len);

        goto err;
    }


    if (__seal_rootkey_and_export(unwrapped_buffer, unwrapped_buflen, sealed_volkey_keybuf_out)) {
        log_error("__seal_rootkey_and_export FAILED\n");
        goto err;
    }

    nexus_free(result);

    return 0;
err:
    nexus_free(result);
    return -1;
}
