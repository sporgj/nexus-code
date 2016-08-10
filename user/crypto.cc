#include <stdlib.h>
#include <string.h>

#include <google/protobuf/repeated_field.h>
#include <glog/logging.h>

extern "C" {
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <uuid/uuid.h>
}

#include "uspace.h"
#include "dirnode.h"
#include "crypto.h"

class dnode_fentry;
using namespace google::protobuf;

crypto_ekey_t sealing_key = { 115, 80, 110, 83,  133, 148, 244, 143,
                              217, 92, 188, 135, 118, 99,  130, 243 };

// temporary
typedef enum { ITER_NOOP, ITER_RM, ITER_PRINT } crypto_iterop_t;

// generates a random number using RDRAND
static int crypto_rand(void * dest, size_t len)
{
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    int ret = mbedtls_entropy_func(&entropy, (uint8_t *)dest, len);
    mbedtls_entropy_free(&entropy);

    return ret;
}

// TODO
static int crypto_mac_fb(DirNode * fb, crypto_mac_t * mac) { return 0; }

static int crypto_ekey(crypto_ekey_t * ekey, crypto_op_t op)
{
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    if (op == ENCRYPT) {
        mbedtls_aes_setkey_enc(&aes_ctx, (uint8_t *)&sealing_key,
                               CRYPTO_AES_KEY_SIZE_BITS);
    } else {
        mbedtls_aes_setkey_dec(&aes_ctx, (uint8_t *)&sealing_key,
                               CRYPTO_AES_KEY_SIZE_BITS);
    }
    mbedtls_aes_crypt_ecb(&aes_ctx, op == ENCRYPT ? MBEDTLS_AES_ENCRYPT
                                                  : MBEDTLS_AES_DECRYPT,
                          (uint8_t *)ekey, (uint8_t *)ekey);
    mbedtls_aes_free(&aes_ctx);
    return 0;
}

static void crypto_rawfname(crypto_ekey_t * ekey, crypto_iv_t * iv, size_t slen,
                            uint8_t * src, uint8_t * dest, crypto_op_t op)
{
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    if (op == ENCRYPT) {
        mbedtls_aes_setkey_enc(&aes_ctx, (uint8_t *)ekey,
                               CRYPTO_AES_KEY_SIZE_BITS);
    } else {
        mbedtls_aes_setkey_dec(&aes_ctx, (uint8_t *)ekey,
                               CRYPTO_AES_KEY_SIZE_BITS);
    }
    mbedtls_aes_crypt_cbc(
        &aes_ctx, (op == ENCRYPT ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
        slen, (uint8_t *)iv, src, dest);
    mbedtls_aes_free(&aes_ctx);
}

int crypto_init_filebox(DirNode * fb)
{
    crypto_ekey_t ekey;
    crypto_mac_t mac;

    crypto_rand(&ekey, sizeof(crypto_ekey_t));
    crypto_ekey(&ekey, ENCRYPT);

    fb->set_ekey(&ekey);
    fb->set_mac(&mac);

    return 0;
}

encoded_fname_t * crypto_add_file(DirNode * fb, const char * fname)
{
    raw_fname_t * fname_malloc;
    size_t slen = CRYPTO_GET_BLK_LEN(strlen(fname));
    encoded_fname_t * encoded_name;

    fname_malloc = (raw_fname_t *)calloc(1, sizeof(raw_fname_t) + slen);
    if (fname_malloc == NULL) {
        LOG(ERROR) << "calloc() error";
        goto out;
    }

    {
        fname_malloc->len = slen;

        memcpy(fname_malloc->data, fname, strlen(fname));

        /* generate a random encoded name */
        encoded_name = new encoded_fname_t;
        uuid_generate_time_safe(encoded_name->bin);

        /* get the encryption key then encrypt the raw filename */
        crypto_ekey_t * ekey = new crypto_ekey_t;
        memcpy(ekey, fb->proto->ekey().data(), sizeof(crypto_ekey_t));
        crypto_ekey(ekey, DECRYPT);

        crypto_iv_t iv, _iv;
        crypto_rand(&iv, sizeof(crypto_iv_t));
        memcpy(&_iv, &iv, sizeof(crypto_iv_t));

        crypto_rawfname(ekey, &iv, slen, fname_malloc->data, fname_malloc->data,
                        ENCRYPT);
        
        fb->add(encoded_name, fname_malloc, &_iv);

        free(fname_malloc);
    }

out:
    return encoded_name;
}

char * crypto_get_fname(DirNode * fb, const encoded_fname_t * codename)
{
    char * result_malloc = nullptr;
    const dnode_fentry * fentry;

    for (size_t i = 0; i < fb->proto->file_size(); i++) {
        fentry = &fb->proto->file(i);

        if (memcmp(codename, fentry->encoded_name().data(),
                   sizeof(encoded_fname_t)) == 0) {
            // we have found the entry
            goto decrypt;
        }
    }
    goto out;

decrypt : {
    /* decrypt the filebox encryption key and get the raw file name */
    size_t slen;

    crypto_iv_t * iv = new crypto_iv_t;
    memcpy(iv, fentry->iv().data(), sizeof(crypto_iv_t));

    // XXX using malloc/free
    raw_fname_t * temp_fname = (raw_fname_t *)fentry->raw_name().data();
    slen = temp_fname->len;
    result_malloc = (char *)malloc(slen);

    crypto_ekey_t * ekey = new crypto_ekey_t;
    memcpy(ekey, fb->proto->ekey().data(), sizeof(crypto_ekey_t));
    crypto_ekey(ekey, DECRYPT);

    crypto_rawfname(ekey, iv, slen, temp_fname->data, (uint8_t *)result_malloc, DECRYPT);

    delete iv;
    delete ekey;
}

out:
    return result_malloc;
}

static encoded_fname_t * __iterate_files(dnode * dn,
                                         const char * plain_filename, bool rm)
{
    encoded_fname_t * result = nullptr;
    raw_fname_t * raw_name;
    crypto_iv_t iv;
    size_t slen = CRYPTO_GET_BLK_LEN(strlen(plain_filename));
    uint8_t * plain_fname = new uint8_t[slen]{ 0 };
    uint8_t * encrypted_fname = new uint8_t[slen];

    memcpy(plain_fname, plain_filename, strlen(plain_filename));

    crypto_ekey_t * ekey = new crypto_ekey_t;
    memcpy(ekey, dn->ekey().data(), sizeof(crypto_ekey_t));
    crypto_ekey(ekey, DECRYPT);

    auto list = dn->mutable_file();
    auto fentry = list->begin();
    while (fentry != list->end()) {
        /* encrypt filename under current IV and ekey */
        memcpy(&iv, fentry->iv().data(), sizeof(crypto_iv_t));

        crypto_rawfname(ekey, &iv, slen, plain_fname, encrypted_fname, ENCRYPT);

        raw_name = (raw_fname_t *)fentry->raw_name().data();
        if (memcmp(encrypted_fname, raw_name->data, slen) == 0) {
            result = new encoded_fname_t;
            memcpy(result, fentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            if (rm) {
                list->erase(fentry);
            }

            break;
        }

        fentry++;
    }

out:
    delete[] plain_fname;
    delete[] encrypted_fname;
    return result;
}

encoded_fname_t * crypto_get_codename(DirNode * fb, const char * plain_filename)
{
    return __iterate_files(fb->proto, plain_filename, false);
}

encoded_fname_t * crypto_remove_file(DirNode * fb, const char * plain_filename)
{
    return __iterate_files(fb->proto, plain_filename, true);
}

void crypto_list_files(DirNode * fb)
{
    crypto_ekey_t * ekey = new crypto_ekey_t;
    memcpy(ekey, fb->proto->ekey().data(), sizeof(crypto_ekey_t));
    crypto_ekey(ekey, DECRYPT);
    crypto_iv_t iv;
    raw_fname_t * raw_name;

    auto list = fb->proto->mutable_file();
    auto fentry = list->begin();

    while (fentry != list->end()) {
        /* encrypt filename under current IV and ekey */
        memcpy(&iv, fentry->iv().data(), sizeof(crypto_iv_t));
        raw_name = (raw_fname_t *)fentry->raw_name().data();

        uint8_t * decrypted_fname = new uint8_t[raw_name->len];

        crypto_rawfname(ekey, &iv, raw_name->len, raw_name->data,
                        decrypted_fname, DECRYPT);
        cout << decrypted_fname << endl;

        fentry++;
    }
}
