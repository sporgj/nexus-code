#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_urts.h>
#include <sgx_tseal.h>

#include <sgx_quote.h>
#include <sgx_uae_service.h>

#include <time.h>

#include "sgx_backend_common.h"

#define ENCLAVE_PATH "./enclave/enclave.signed.so"

#define SGX_VERIFY_URL "https://test-as.sgx.trustedservices.intel.com/attestation/sgx/v2/report"

#define SGX_CERT_PATH "./tls-cert/prognosticlab-sgx.cert"
#define SGX_KEY_PATH "./tls-cert/client.key"
#define SGX_KEY_PASS "foobar"


extern sgx_spid_t global_spid;


// all the messages
struct nxs_instance {
    sgx_quote_t            * quote;

    uint32_t                 quote_size;

    struct ecdh_public_key   pubkey;

    uint8_t                * sealed_privkey;

    uint32_t                 privkey_size;
};


struct rk_exchange {
    struct ecdh_public_key   ephemeral_pubkey;

    struct ecdh_nonce        nonce;

    uint8_t                * ciphertext;

    uint32_t                 ciphertext_len;
};



int
store_init_message(const char * filepath, struct nxs_instance * message);

struct nxs_instance *
fetch_init_message(const char * filepath);

void
free_init_message(struct nxs_instance * message);



int
store_xchg_message(const char * filepath, struct rk_exchange * message);

struct rk_exchange *
fetch_xchg_message(const char * filepath);

void
free_xchg_message(struct rk_exchange * message);


/* quote.c */
sgx_quote_t *
generate_quote(sgx_report_t * report, uint32_t * p_quote_size);

int
validate_quote(sgx_quote_t * quote, uint32_t quote_size);



/* protocol.c */
struct nxs_instance *
create_nxs_instance();

int
mount_nxs_instance(struct nxs_instance * nxs_instance, sgx_enclave_id_t enclave_id);

struct rk_exchange *
create_rk_exchange(struct nxs_instance * other_instance, sgx_enclave_id_t enclave_id);

uint8_t *
extract_rk_secret(struct rk_exchange * message, sgx_enclave_id_t enclave_id, int * len);

