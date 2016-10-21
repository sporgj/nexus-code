#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "uc_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int ecall_init_enclave();
int ecall_init_crypto(xfer_context_t* f_ctx, crypto_context_t* fcrypto);
int ecall_crypt_data(xfer_context_t* f_ctx);
int ecall_finish_crypto(xfer_context_t* f_ctx, crypto_context_t* fcrypto);
int ecall_crypto_dirnode(dnode_header_t* header, uint8_t* data, uc_crypto_op_t op);
int ecall_crypto_filebox(fbox_header_t* header, uint8_t* data, uc_crypto_op_t op);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
