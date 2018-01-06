#include "nexus_enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_enclave_t {
	int ms_retval;
	void* ms_backend_info;
} ms_ecall_init_enclave_t;

typedef struct ms_ecall_create_volume_t {
	int ms_retval;
	struct raw_buffer* ms_user_pubkey_in;
	struct nexus_uuid* ms_supernode_uuid_out;
	struct sealed_buffer** ms_sealed_volumekey_out;
} ms_ecall_create_volume_t;

typedef struct ms_ecall_auth_request_t {
	int ms_retval;
	struct raw_buffer* ms_user_pubkey_in;
	struct sealed_buffer* ms_sealed_volkey_in;
	struct raw_buffer** ms_nonce_challenge_out;
} ms_ecall_auth_request_t;

typedef struct ms_ecall_auth_response_t {
	int ms_retval;
	struct crypto_buffer* ms_supernode_in;
	struct raw_buffer* ms_signature_in;
} ms_ecall_auth_response_t;

typedef struct ms_ocall_metadata_get_t {
	struct crypto_buffer* ms_retval;
	struct nexus_uuid* ms_uuid;
	struct nexus_uuid_path* ms_uuid_path_untrusted;
	void* ms_backend_info;
} ms_ocall_metadata_get_t;

typedef struct ms_ocall_metadata_set_t {
	int ms_retval;
	struct nexus_uuid* ms_uuid;
	struct nexus_uuid_path* ms_uuid_path_untrusted;
	struct crypto_buffer* ms_crypto_buffer;
	void* ms_backend_info;
} ms_ocall_metadata_set_t;

typedef struct ms_ocall_metadata_delete_t {
	int ms_retval;
	struct nexus_uuid* ms_uuid;
	struct nexus_uuid_path* ms_uuid_path_untrusted;
	void* ms_backend_info;
} ms_ocall_metadata_delete_t;

typedef struct ms_ocall_metadata_stat_t {
	int ms_retval;
	struct nexus_uuid* ms_uuid;
	struct nexus_uuid_path* ms_uuid_path_untrusted;
	struct nexus_stat_buffer* ms_stat_buffer_untrusted;
	void* ms_backend_info;
} ms_ocall_metadata_stat_t;

typedef struct ms_ocall_calloc_t {
	void* ms_retval;
	size_t ms_size;
} ms_ocall_calloc_t;

typedef struct ms_ocall_free_t {
	void* ms_untrusted_ptr;
} ms_ocall_free_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL nexus_enclave_ocall_metadata_get(void* pms)
{
	ms_ocall_metadata_get_t* ms = SGX_CAST(ms_ocall_metadata_get_t*, pms);
	ms->ms_retval = ocall_metadata_get(ms->ms_uuid, ms->ms_uuid_path_untrusted, ms->ms_backend_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nexus_enclave_ocall_metadata_set(void* pms)
{
	ms_ocall_metadata_set_t* ms = SGX_CAST(ms_ocall_metadata_set_t*, pms);
	ms->ms_retval = ocall_metadata_set(ms->ms_uuid, ms->ms_uuid_path_untrusted, ms->ms_crypto_buffer, ms->ms_backend_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nexus_enclave_ocall_metadata_delete(void* pms)
{
	ms_ocall_metadata_delete_t* ms = SGX_CAST(ms_ocall_metadata_delete_t*, pms);
	ms->ms_retval = ocall_metadata_delete(ms->ms_uuid, ms->ms_uuid_path_untrusted, ms->ms_backend_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nexus_enclave_ocall_metadata_stat(void* pms)
{
	ms_ocall_metadata_stat_t* ms = SGX_CAST(ms_ocall_metadata_stat_t*, pms);
	ms->ms_retval = ocall_metadata_stat(ms->ms_uuid, ms->ms_uuid_path_untrusted, ms->ms_stat_buffer_untrusted, ms->ms_backend_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nexus_enclave_ocall_calloc(void* pms)
{
	ms_ocall_calloc_t* ms = SGX_CAST(ms_ocall_calloc_t*, pms);
	ms->ms_retval = ocall_calloc(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nexus_enclave_ocall_free(void* pms)
{
	ms_ocall_free_t* ms = SGX_CAST(ms_ocall_free_t*, pms);
	ocall_free(ms->ms_untrusted_ptr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL nexus_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_nexus_enclave = {
	7,
	{
		(void*)nexus_enclave_ocall_metadata_get,
		(void*)nexus_enclave_ocall_metadata_set,
		(void*)nexus_enclave_ocall_metadata_delete,
		(void*)nexus_enclave_ocall_metadata_stat,
		(void*)nexus_enclave_ocall_calloc,
		(void*)nexus_enclave_ocall_free,
		(void*)nexus_enclave_ocall_print,
	}
};
sgx_status_t ecall_init_enclave(sgx_enclave_id_t eid, int* retval, void* backend_info)
{
	sgx_status_t status;
	ms_ecall_init_enclave_t ms;
	ms.ms_backend_info = backend_info;
	status = sgx_ecall(eid, 0, &ocall_table_nexus_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_volume(sgx_enclave_id_t eid, int* retval, struct raw_buffer* user_pubkey_in, struct nexus_uuid* supernode_uuid_out, struct sealed_buffer** sealed_volumekey_out)
{
	sgx_status_t status;
	ms_ecall_create_volume_t ms;
	ms.ms_user_pubkey_in = user_pubkey_in;
	ms.ms_supernode_uuid_out = supernode_uuid_out;
	ms.ms_sealed_volumekey_out = sealed_volumekey_out;
	status = sgx_ecall(eid, 1, &ocall_table_nexus_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_auth_request(sgx_enclave_id_t eid, int* retval, struct raw_buffer* user_pubkey_in, struct sealed_buffer* sealed_volkey_in, struct raw_buffer** nonce_challenge_out)
{
	sgx_status_t status;
	ms_ecall_auth_request_t ms;
	ms.ms_user_pubkey_in = user_pubkey_in;
	ms.ms_sealed_volkey_in = sealed_volkey_in;
	ms.ms_nonce_challenge_out = nonce_challenge_out;
	status = sgx_ecall(eid, 2, &ocall_table_nexus_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_auth_response(sgx_enclave_id_t eid, int* retval, struct crypto_buffer* supernode_in, struct raw_buffer* signature_in)
{
	sgx_status_t status;
	ms_ecall_auth_response_t ms;
	ms.ms_supernode_in = supernode_in;
	ms.ms_signature_in = signature_in;
	status = sgx_ecall(eid, 3, &ocall_table_nexus_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

