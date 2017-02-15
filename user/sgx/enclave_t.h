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
int ecall_crypto_dirnode(dnode_header_t* header, uint8_t* data, uc_crypto_op_t op);
int ecall_crypto_filebox(fbox_header_t* header, uint8_t* data, uc_crypto_op_t op);
int ecall_fetchstore_init(xfer_context_t* xfer_ctx);
int ecall_fetchstore_start(xfer_context_t* xfer_ctx);
int ecall_fetchstore_crypto(xfer_context_t* xfer_ctx);
int ecall_fetchstore_finish(xfer_context_t* xfer_ctx);
int ecall_initialize(supernode_t* supernode, char* pubkey_str, size_t keylen);
int ecall_ucafs_challenge(uint8_t* nonce_a, auth_struct_t* auth);
int ecall_ucafs_response(supernode_t* super, char* pubkey_str, size_t keylen, uint8_t* user_signature, size_t sig_len);
int ecall_supernode_crypto(supernode_t* supernode, seal_op_t op);
int ecall_supernode_mount(supernode_t* supernode);
int ecall_check_rights(dnode_header_t* dnode_head, acl_head_t* acl_list, acl_rights_t rights);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
