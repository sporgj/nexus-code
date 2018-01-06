#ifndef NEXUS_ENCLAVE_U_H__
#define NEXUS_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "internal.h"
#include "sgx_backend_common.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

struct crypto_buffer* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_metadata_get, (struct nexus_uuid* uuid, struct nexus_uuid_path* uuid_path_untrusted, void* backend_info));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_metadata_set, (struct nexus_uuid* uuid, struct nexus_uuid_path* uuid_path_untrusted, struct crypto_buffer* crypto_buffer, void* backend_info));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_metadata_delete, (struct nexus_uuid* uuid, struct nexus_uuid_path* uuid_path_untrusted, void* backend_info));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_metadata_stat, (struct nexus_uuid* uuid, struct nexus_uuid_path* uuid_path_untrusted, struct nexus_stat_buffer* stat_buffer_untrusted, void* backend_info));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_calloc, (size_t size));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (void* untrusted_ptr));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (char* str));

sgx_status_t ecall_init_enclave(sgx_enclave_id_t eid, int* retval, void* backend_info);
sgx_status_t ecall_create_volume(sgx_enclave_id_t eid, int* retval, struct raw_buffer* user_pubkey_in, struct nexus_uuid* supernode_uuid_out, struct sealed_buffer** sealed_volumekey_out);
sgx_status_t ecall_auth_request(sgx_enclave_id_t eid, int* retval, struct raw_buffer* user_pubkey_in, struct sealed_buffer* sealed_volkey_in, struct raw_buffer** nonce_challenge_out);
sgx_status_t ecall_auth_response(sgx_enclave_id_t eid, int* retval, struct crypto_buffer* supernode_in, struct raw_buffer* signature_in);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
