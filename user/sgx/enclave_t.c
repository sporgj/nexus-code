#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_init_enclave_t {
	int ms_retval;
} ms_ecall_init_enclave_t;

typedef struct ms_ecall_crypto_dirnode_t {
	int ms_retval;
	dnode_header_t* ms_header;
	uint8_t* ms_data;
	uc_crypto_op_t ms_op;
} ms_ecall_crypto_dirnode_t;

typedef struct ms_ecall_crypto_filebox_t {
	int ms_retval;
	fbox_header_t* ms_header;
	uint8_t* ms_data;
	uc_crypto_op_t ms_op;
} ms_ecall_crypto_filebox_t;

typedef struct ms_ecall_fetchstore_init_t {
	int ms_retval;
	xfer_context_t* ms_xfer_ctx;
} ms_ecall_fetchstore_init_t;

typedef struct ms_ecall_fetchstore_start_t {
	int ms_retval;
	xfer_context_t* ms_xfer_ctx;
} ms_ecall_fetchstore_start_t;

typedef struct ms_ecall_fetchstore_crypto_t {
	int ms_retval;
	xfer_context_t* ms_xfer_ctx;
} ms_ecall_fetchstore_crypto_t;

typedef struct ms_ecall_fetchstore_finish_t {
	int ms_retval;
	xfer_context_t* ms_xfer_ctx;
} ms_ecall_fetchstore_finish_t;

typedef struct ms_ecall_initialize_t {
	int ms_retval;
	supernode_t* ms_supernode;
	char* ms_pubkey_str;
	size_t ms_keylen;
} ms_ecall_initialize_t;

typedef struct ms_ecall_ucafs_challenge_t {
	int ms_retval;
	uint8_t* ms_nonce_a;
	auth_struct_t* ms_auth;
} ms_ecall_ucafs_challenge_t;

typedef struct ms_ecall_ucafs_response_t {
	int ms_retval;
	supernode_t* ms_super;
	char* ms_pubkey_str;
	size_t ms_keylen;
	uint8_t* ms_user_signature;
	size_t ms_sig_len;
} ms_ecall_ucafs_response_t;

typedef struct ms_ecall_supernode_crypto_t {
	int ms_retval;
	supernode_t* ms_supernode;
	seal_op_t ms_op;
} ms_ecall_supernode_crypto_t;

typedef struct ms_ecall_supernode_mount_t {
	int ms_retval;
	supernode_t* ms_supernode;
} ms_ecall_supernode_mount_t;

typedef struct ms_ecall_check_rights_t {
	int ms_retval;
	dnode_header_t* ms_dnode_head;
	acl_head_t* ms_acl_list;
	acl_rights_t ms_rights;
} ms_ecall_check_rights_t;

static sgx_status_t SGX_CDECL sgx_ecall_init_enclave(void* pms)
{
	ms_ecall_init_enclave_t* ms = SGX_CAST(ms_ecall_init_enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_enclave_t));

	ms->ms_retval = ecall_init_enclave();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_crypto_dirnode(void* pms)
{
	ms_ecall_crypto_dirnode_t* ms = SGX_CAST(ms_ecall_crypto_dirnode_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	dnode_header_t* _tmp_header = ms->ms_header;
	size_t _len_header = sizeof(*_tmp_header);
	dnode_header_t* _in_header = NULL;
	uint8_t* _tmp_data = ms->ms_data;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_crypto_dirnode_t));
	CHECK_UNIQUE_POINTER(_tmp_header, _len_header);

	if (_tmp_header != NULL) {
		_in_header = (dnode_header_t*)malloc(_len_header);
		if (_in_header == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_header, _tmp_header, _len_header);
	}
	ms->ms_retval = ecall_crypto_dirnode(_in_header, _tmp_data, ms->ms_op);
err:
	if (_in_header) {
		memcpy(_tmp_header, _in_header, _len_header);
		free(_in_header);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_crypto_filebox(void* pms)
{
	ms_ecall_crypto_filebox_t* ms = SGX_CAST(ms_ecall_crypto_filebox_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	fbox_header_t* _tmp_header = ms->ms_header;
	size_t _len_header = sizeof(*_tmp_header);
	fbox_header_t* _in_header = NULL;
	uint8_t* _tmp_data = ms->ms_data;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_crypto_filebox_t));
	CHECK_UNIQUE_POINTER(_tmp_header, _len_header);

	if (_tmp_header != NULL) {
		_in_header = (fbox_header_t*)malloc(_len_header);
		if (_in_header == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_header, _tmp_header, _len_header);
	}
	ms->ms_retval = ecall_crypto_filebox(_in_header, _tmp_data, ms->ms_op);
err:
	if (_in_header) {
		memcpy(_tmp_header, _in_header, _len_header);
		free(_in_header);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fetchstore_init(void* pms)
{
	ms_ecall_fetchstore_init_t* ms = SGX_CAST(ms_ecall_fetchstore_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_xfer_ctx = ms->ms_xfer_ctx;
	size_t _len_xfer_ctx = sizeof(*_tmp_xfer_ctx);
	xfer_context_t* _in_xfer_ctx = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fetchstore_init_t));
	CHECK_UNIQUE_POINTER(_tmp_xfer_ctx, _len_xfer_ctx);

	if (_tmp_xfer_ctx != NULL) {
		_in_xfer_ctx = (xfer_context_t*)malloc(_len_xfer_ctx);
		if (_in_xfer_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_xfer_ctx, _tmp_xfer_ctx, _len_xfer_ctx);
	}
	ms->ms_retval = ecall_fetchstore_init(_in_xfer_ctx);
err:
	if (_in_xfer_ctx) {
		memcpy(_tmp_xfer_ctx, _in_xfer_ctx, _len_xfer_ctx);
		free(_in_xfer_ctx);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fetchstore_start(void* pms)
{
	ms_ecall_fetchstore_start_t* ms = SGX_CAST(ms_ecall_fetchstore_start_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_xfer_ctx = ms->ms_xfer_ctx;
	size_t _len_xfer_ctx = sizeof(*_tmp_xfer_ctx);
	xfer_context_t* _in_xfer_ctx = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fetchstore_start_t));
	CHECK_UNIQUE_POINTER(_tmp_xfer_ctx, _len_xfer_ctx);

	if (_tmp_xfer_ctx != NULL) {
		_in_xfer_ctx = (xfer_context_t*)malloc(_len_xfer_ctx);
		if (_in_xfer_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_xfer_ctx, _tmp_xfer_ctx, _len_xfer_ctx);
	}
	ms->ms_retval = ecall_fetchstore_start(_in_xfer_ctx);
err:
	if (_in_xfer_ctx) {
		memcpy(_tmp_xfer_ctx, _in_xfer_ctx, _len_xfer_ctx);
		free(_in_xfer_ctx);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fetchstore_crypto(void* pms)
{
	ms_ecall_fetchstore_crypto_t* ms = SGX_CAST(ms_ecall_fetchstore_crypto_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_xfer_ctx = ms->ms_xfer_ctx;
	size_t _len_xfer_ctx = sizeof(*_tmp_xfer_ctx);
	xfer_context_t* _in_xfer_ctx = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fetchstore_crypto_t));
	CHECK_UNIQUE_POINTER(_tmp_xfer_ctx, _len_xfer_ctx);

	if (_tmp_xfer_ctx != NULL) {
		_in_xfer_ctx = (xfer_context_t*)malloc(_len_xfer_ctx);
		if (_in_xfer_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_xfer_ctx, _tmp_xfer_ctx, _len_xfer_ctx);
	}
	ms->ms_retval = ecall_fetchstore_crypto(_in_xfer_ctx);
err:
	if (_in_xfer_ctx) {
		memcpy(_tmp_xfer_ctx, _in_xfer_ctx, _len_xfer_ctx);
		free(_in_xfer_ctx);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fetchstore_finish(void* pms)
{
	ms_ecall_fetchstore_finish_t* ms = SGX_CAST(ms_ecall_fetchstore_finish_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_xfer_ctx = ms->ms_xfer_ctx;
	size_t _len_xfer_ctx = sizeof(*_tmp_xfer_ctx);
	xfer_context_t* _in_xfer_ctx = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fetchstore_finish_t));
	CHECK_UNIQUE_POINTER(_tmp_xfer_ctx, _len_xfer_ctx);

	if (_tmp_xfer_ctx != NULL) {
		_in_xfer_ctx = (xfer_context_t*)malloc(_len_xfer_ctx);
		if (_in_xfer_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_xfer_ctx, _tmp_xfer_ctx, _len_xfer_ctx);
	}
	ms->ms_retval = ecall_fetchstore_finish(_in_xfer_ctx);
err:
	if (_in_xfer_ctx) {
		memcpy(_tmp_xfer_ctx, _in_xfer_ctx, _len_xfer_ctx);
		free(_in_xfer_ctx);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_initialize(void* pms)
{
	ms_ecall_initialize_t* ms = SGX_CAST(ms_ecall_initialize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	supernode_t* _tmp_supernode = ms->ms_supernode;
	char* _tmp_pubkey_str = ms->ms_pubkey_str;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_initialize_t));

	ms->ms_retval = ecall_initialize(_tmp_supernode, _tmp_pubkey_str, ms->ms_keylen);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ucafs_challenge(void* pms)
{
	ms_ecall_ucafs_challenge_t* ms = SGX_CAST(ms_ecall_ucafs_challenge_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_nonce_a = ms->ms_nonce_a;
	auth_struct_t* _tmp_auth = ms->ms_auth;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ucafs_challenge_t));

	ms->ms_retval = ecall_ucafs_challenge(_tmp_nonce_a, _tmp_auth);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ucafs_response(void* pms)
{
	ms_ecall_ucafs_response_t* ms = SGX_CAST(ms_ecall_ucafs_response_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	supernode_t* _tmp_super = ms->ms_super;
	size_t _len_super = sizeof(*_tmp_super);
	supernode_t* _in_super = NULL;
	char* _tmp_pubkey_str = ms->ms_pubkey_str;
	uint8_t* _tmp_user_signature = ms->ms_user_signature;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ucafs_response_t));
	CHECK_UNIQUE_POINTER(_tmp_super, _len_super);

	if (_tmp_super != NULL) {
		_in_super = (supernode_t*)malloc(_len_super);
		if (_in_super == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_super, _tmp_super, _len_super);
	}
	ms->ms_retval = ecall_ucafs_response(_in_super, _tmp_pubkey_str, ms->ms_keylen, _tmp_user_signature, ms->ms_sig_len);
err:
	if (_in_super) free(_in_super);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_supernode_crypto(void* pms)
{
	ms_ecall_supernode_crypto_t* ms = SGX_CAST(ms_ecall_supernode_crypto_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	supernode_t* _tmp_supernode = ms->ms_supernode;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_supernode_crypto_t));

	ms->ms_retval = ecall_supernode_crypto(_tmp_supernode, ms->ms_op);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_supernode_mount(void* pms)
{
	ms_ecall_supernode_mount_t* ms = SGX_CAST(ms_ecall_supernode_mount_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	supernode_t* _tmp_supernode = ms->ms_supernode;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_supernode_mount_t));

	ms->ms_retval = ecall_supernode_mount(_tmp_supernode);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_check_rights(void* pms)
{
	ms_ecall_check_rights_t* ms = SGX_CAST(ms_ecall_check_rights_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	dnode_header_t* _tmp_dnode_head = ms->ms_dnode_head;
	size_t _len_dnode_head = sizeof(*_tmp_dnode_head);
	dnode_header_t* _in_dnode_head = NULL;
	acl_head_t* _tmp_acl_list = ms->ms_acl_list;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_check_rights_t));
	CHECK_UNIQUE_POINTER(_tmp_dnode_head, _len_dnode_head);

	if (_tmp_dnode_head != NULL) {
		_in_dnode_head = (dnode_header_t*)malloc(_len_dnode_head);
		if (_in_dnode_head == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_dnode_head, _tmp_dnode_head, _len_dnode_head);
	}
	ms->ms_retval = ecall_check_rights(_in_dnode_head, _tmp_acl_list, ms->ms_rights);
err:
	if (_in_dnode_head) free(_in_dnode_head);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[13];
} g_ecall_table = {
	13,
	{
		{(void*)(uintptr_t)sgx_ecall_init_enclave, 0},
		{(void*)(uintptr_t)sgx_ecall_crypto_dirnode, 0},
		{(void*)(uintptr_t)sgx_ecall_crypto_filebox, 0},
		{(void*)(uintptr_t)sgx_ecall_fetchstore_init, 0},
		{(void*)(uintptr_t)sgx_ecall_fetchstore_start, 0},
		{(void*)(uintptr_t)sgx_ecall_fetchstore_crypto, 0},
		{(void*)(uintptr_t)sgx_ecall_fetchstore_finish, 0},
		{(void*)(uintptr_t)sgx_ecall_initialize, 0},
		{(void*)(uintptr_t)sgx_ecall_ucafs_challenge, 0},
		{(void*)(uintptr_t)sgx_ecall_ucafs_response, 0},
		{(void*)(uintptr_t)sgx_ecall_supernode_crypto, 0},
		{(void*)(uintptr_t)sgx_ecall_supernode_mount, 0},
		{(void*)(uintptr_t)sgx_ecall_check_rights, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


