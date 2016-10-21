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

typedef struct ms_ecall_init_crypto_t {
	int ms_retval;
	xfer_context_t* ms_f_ctx;
	crypto_context_t* ms_fcrypto;
} ms_ecall_init_crypto_t;

typedef struct ms_ecall_crypt_data_t {
	int ms_retval;
	xfer_context_t* ms_f_ctx;
} ms_ecall_crypt_data_t;

typedef struct ms_ecall_finish_crypto_t {
	int ms_retval;
	xfer_context_t* ms_f_ctx;
	crypto_context_t* ms_fcrypto;
} ms_ecall_finish_crypto_t;

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

static sgx_status_t SGX_CDECL sgx_ecall_init_enclave(void* pms)
{
	ms_ecall_init_enclave_t* ms = SGX_CAST(ms_ecall_init_enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_enclave_t));

	ms->ms_retval = ecall_init_enclave();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_crypto(void* pms)
{
	ms_ecall_init_crypto_t* ms = SGX_CAST(ms_ecall_init_crypto_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_f_ctx = ms->ms_f_ctx;
	size_t _len_f_ctx = sizeof(*_tmp_f_ctx);
	xfer_context_t* _in_f_ctx = NULL;
	crypto_context_t* _tmp_fcrypto = ms->ms_fcrypto;
	size_t _len_fcrypto = sizeof(*_tmp_fcrypto);
	crypto_context_t* _in_fcrypto = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_crypto_t));
	CHECK_UNIQUE_POINTER(_tmp_f_ctx, _len_f_ctx);
	CHECK_UNIQUE_POINTER(_tmp_fcrypto, _len_fcrypto);

	if (_tmp_f_ctx != NULL) {
		_in_f_ctx = (xfer_context_t*)malloc(_len_f_ctx);
		if (_in_f_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_f_ctx, _tmp_f_ctx, _len_f_ctx);
	}
	if (_tmp_fcrypto != NULL) {
		_in_fcrypto = (crypto_context_t*)malloc(_len_fcrypto);
		if (_in_fcrypto == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fcrypto, _tmp_fcrypto, _len_fcrypto);
	}
	ms->ms_retval = ecall_init_crypto(_in_f_ctx, _in_fcrypto);
err:
	if (_in_f_ctx) {
		memcpy(_tmp_f_ctx, _in_f_ctx, _len_f_ctx);
		free(_in_f_ctx);
	}
	if (_in_fcrypto) free(_in_fcrypto);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_crypt_data(void* pms)
{
	ms_ecall_crypt_data_t* ms = SGX_CAST(ms_ecall_crypt_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_f_ctx = ms->ms_f_ctx;
	size_t _len_f_ctx = sizeof(*_tmp_f_ctx);
	xfer_context_t* _in_f_ctx = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_crypt_data_t));
	CHECK_UNIQUE_POINTER(_tmp_f_ctx, _len_f_ctx);

	if (_tmp_f_ctx != NULL) {
		_in_f_ctx = (xfer_context_t*)malloc(_len_f_ctx);
		if (_in_f_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_f_ctx, _tmp_f_ctx, _len_f_ctx);
	}
	ms->ms_retval = ecall_crypt_data(_in_f_ctx);
err:
	if (_in_f_ctx) {
		memcpy(_tmp_f_ctx, _in_f_ctx, _len_f_ctx);
		free(_in_f_ctx);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_finish_crypto(void* pms)
{
	ms_ecall_finish_crypto_t* ms = SGX_CAST(ms_ecall_finish_crypto_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	xfer_context_t* _tmp_f_ctx = ms->ms_f_ctx;
	size_t _len_f_ctx = sizeof(*_tmp_f_ctx);
	xfer_context_t* _in_f_ctx = NULL;
	crypto_context_t* _tmp_fcrypto = ms->ms_fcrypto;
	size_t _len_fcrypto = sizeof(*_tmp_fcrypto);
	crypto_context_t* _in_fcrypto = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_finish_crypto_t));
	CHECK_UNIQUE_POINTER(_tmp_f_ctx, _len_f_ctx);
	CHECK_UNIQUE_POINTER(_tmp_fcrypto, _len_fcrypto);

	if (_tmp_f_ctx != NULL) {
		_in_f_ctx = (xfer_context_t*)malloc(_len_f_ctx);
		if (_in_f_ctx == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_f_ctx, _tmp_f_ctx, _len_f_ctx);
	}
	if (_tmp_fcrypto != NULL) {
		_in_fcrypto = (crypto_context_t*)malloc(_len_fcrypto);
		if (_in_fcrypto == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_fcrypto, _tmp_fcrypto, _len_fcrypto);
	}
	ms->ms_retval = ecall_finish_crypto(_in_f_ctx, _in_fcrypto);
err:
	if (_in_f_ctx) free(_in_f_ctx);
	if (_in_fcrypto) {
		memcpy(_tmp_fcrypto, _in_fcrypto, _len_fcrypto);
		free(_in_fcrypto);
	}

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

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_init_enclave, 0},
		{(void*)(uintptr_t)sgx_ecall_init_crypto, 0},
		{(void*)(uintptr_t)sgx_ecall_crypt_data, 0},
		{(void*)(uintptr_t)sgx_ecall_finish_crypto, 0},
		{(void*)(uintptr_t)sgx_ecall_crypto_dirnode, 0},
		{(void*)(uintptr_t)sgx_ecall_crypto_filebox, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


