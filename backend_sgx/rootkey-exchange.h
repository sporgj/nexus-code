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

    int                      ciphertext_len;

    struct nexus_uuid        volume_uuid;
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

