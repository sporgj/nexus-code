#include "internal.h"

#include <nexus_encode.h>

int
write_keypair(const char             * filepath,
              uint8_t                * quote,
              uint32_t                 quote_len,
              struct ecdh_public_key * pubkey,
              uint8_t                * sealed_privkey,
              uint32_t                 sealed_privkey_len)
{
    char * quote_str   = NULL;
    char * pubkey_str  = NULL;
    char * privkey_str = NULL;


    quote_str = nexus_alt64_encode(quote, quote_len);
    pubkey_str = nexus_alt64_encode(pubkey->bytes, sizeof(struct ecdh_public_key));
    privkey_str = nexus_alt64_encode(sealed_privkey, sealed_privkey_len);

    {
        nexus_json_obj_t json_obj = nexus_json_new_obj(".");

        int ret = 0;

        ret |= nexus_json_add_string(json_obj, "pubkey", pubkey_str);
        ret |= nexus_json_add_string(json_obj, "privkey", privkey_str);
        ret |= nexus_json_add_string(json_obj, "quote", quote_str);

        if (ret) {
            log_error("could not create JSON object\n");
            goto err;
        }

        if (nexus_json_serialize_to_file(json_obj, (char *)filepath)) {
            log_error("nexus_json_serialize_to_file() FAILED\n");
            goto err;
        }

        nexus_json_free(json_obj);
    }

    nexus_free(quote_str);
    nexus_free(pubkey_str);
    nexus_free(privkey_str);

    return 0;
err:
    nexus_free(quote_str);
    nexus_free(pubkey_str);
    nexus_free(privkey_str);

    return -1;
}

int
read_keypair (const char              * filepath,
              uint8_t                ** quote,
              uint32_t                * quote_len,
              struct ecdh_public_key  * pubkey,
              uint8_t                ** sealed_privkey,
              uint32_t                * sealed_privkey_len)
{
    char * quote_str   = NULL;
    char * pubkey_str  = NULL;
    char * privkey_str = NULL;

    uint8_t  * pubkey_buf = NULL;
    uint32_t   pubkey_len = 0;

    nexus_json_obj_t json_obj = NEXUS_JSON_INVALID_OBJ;

    int ret = -1;

    {
        json_obj = nexus_json_parse_file((char *)filepath);

        if (json_obj == NEXUS_JSON_INVALID_OBJ) {
            log_error("could not parse file: %s\n", filepath);
            return -1;
        }

        if (nexus_json_get_string(json_obj, "quote", &quote_str)) {
            log_error("could not get `quote` from JSON object\n");
            goto out;
        }

        if (nexus_json_get_string(json_obj, "pubkey", &pubkey_str)) {
            log_error("could not get `pubkey` from JSON object\n");
            goto out;
        }

        if (nexus_json_get_string(json_obj, "privkey", &privkey_str)) {
            log_error("could not get `privkey` from JSON object\n");
            goto out;
        }
    }

    ret = 0;

    ret |= nexus_alt64_decode(quote_str, quote, (uint32_t *)quote_len);
    ret |= nexus_alt64_decode(pubkey_str, &pubkey_buf, &pubkey_len);
    ret |= nexus_alt64_decode(privkey_str, sealed_privkey, sealed_privkey_len);

    memcpy(pubkey->bytes, pubkey_buf, sizeof(struct ecdh_public_key));
    nexus_free(pubkey_buf);
out:
    if (json_obj != NEXUS_JSON_INVALID_OBJ) {
        nexus_json_free(json_obj);
    }

    return ret;
}

int
store_init_message(const char * filepath, struct nxs_instance * message)
{
    return write_keypair(filepath,
                        (uint8_t *)message->quote,
                        message->quote_size,
                        &message->pubkey,
                        message->sealed_privkey,
                        message->privkey_size);
}

struct nxs_instance *
fetch_init_message(const char * filepath)
{
    struct nxs_instance * result = nexus_malloc(sizeof(struct nxs_instance));

    int ret = read_keypair(filepath,
                           (uint8_t **)&result->quote,
                           &result->quote_size,
                           &result->pubkey,
                           &result->sealed_privkey,
                           &result->privkey_size);

    if (ret) {
        nexus_free(result);
        return NULL;
    }

    return result;
}

void
free_init_message(struct nxs_instance * message)
{
    if (message->quote) {
        nexus_free(message->quote);
    }

    if (message->sealed_privkey) {
        nexus_free(message->sealed_privkey);
    }

    nexus_free(message);
}


int
store_xchg_message(const char * filepath, struct rk_exchange * message)
{
    char * nonce_str = NULL;
    char * ciphertext_str = NULL;
    char * ephemeral_pk_str = NULL;

    nonce_str = nexus_alt64_encode(message->nonce.bytes, sizeof(struct ecdh_nonce));
    ciphertext_str = nexus_alt64_encode(message->ciphertext, message->ciphertext_len);
    ephemeral_pk_str
        = nexus_alt64_encode((uint8_t *)&message->ephemeral_pubkey, sizeof(struct ecdh_public_key));

    {
        nexus_json_obj_t json_obj = nexus_json_new_obj(".");

        int ret = 0;

        ret |= nexus_json_add_string(json_obj, "nonce", nonce_str);
        ret |= nexus_json_add_string(json_obj, "ctext", ciphertext_str);
        ret |= nexus_json_add_string(json_obj, "pubkey", ephemeral_pk_str);

        if (ret) {
            log_error("could not create JSON object\n");
            goto err;
        }

        if (nexus_json_serialize_to_file(json_obj, (char *)filepath)) {
            log_error("nexus_json_serialize_to_file() FAILED\n");
            goto err;
        }

        nexus_json_free(json_obj);
    }

    nexus_free(nonce_str);
    nexus_free(ciphertext_str);
    nexus_free(ephemeral_pk_str);

    return 0;
err:
    nexus_free(nonce_str);
    nexus_free(ciphertext_str);
    nexus_free(ephemeral_pk_str);

    return -1;
}

struct rk_exchange *
fetch_xchg_message(const char * filepath)
{
    struct rk_exchange * message = NULL;

    char * nonce_str = NULL;
    char * ciphertext_str = NULL;
    char * ephemeral_pk_str = NULL;

    uint8_t * nonce_buf  = NULL;
    uint8_t * pubkey_buf = NULL;
    uint32_t  nonce_len  = 0;
    uint32_t  pubkey_len = 0;

    nexus_json_obj_t json_obj = NEXUS_JSON_INVALID_OBJ;

    int ret = -1;

    {
        json_obj = nexus_json_parse_file((char *)filepath);

        if (json_obj == NEXUS_JSON_INVALID_OBJ) {
            log_error("could not parse file: %s\n", filepath);
            return NULL;
        }

        if (nexus_json_get_string(json_obj, "nonce", &nonce_str)) {
            log_error("could not get `nonce` from JSON object\n");
            goto out;
        }

        if (nexus_json_get_string(json_obj, "ctext", &ciphertext_str)) {
            log_error("could not get `ctext` from JSON object\n");
            goto out;
        }

        if (nexus_json_get_string(json_obj, "pubkey", &ephemeral_pk_str)) {
            log_error("could not get `pubkey` from JSON object\n");
            goto out;
        }
    }


    ret = 0;

    message = nexus_malloc(sizeof(struct rk_exchange));

    ret |= nexus_alt64_decode(nonce_str, &nonce_buf, &nonce_len);
    ret |= nexus_alt64_decode(ephemeral_pk_str, &pubkey_buf, &pubkey_len);
    ret |= nexus_alt64_decode(ciphertext_str, &message->ciphertext, &message->ciphertext_len);

    memcpy(message->ephemeral_pubkey.bytes, pubkey_buf, sizeof(struct ecdh_public_key));
    memcpy(message->nonce.bytes, nonce_buf, sizeof(struct ecdh_nonce));
out:
    nexus_free(nonce_buf);
    nexus_free(pubkey_buf);

    nexus_json_free(json_obj);

    if (ret) {
        free_xchg_message(message);
        return NULL;
    }

    return message;
}

void
free_xchg_message(struct rk_exchange * message)
{
    if (message->ciphertext) {
        nexus_free(message->ciphertext);
    }

    nexus_free(message);
}
