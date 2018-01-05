#include "internal.h"

struct crypto_buffer *
crypto_buffer_alloc(void * untrusted_addr, size_t size)
{
    struct crypto_buffer * crypto_buffer = NULL;

    crypto_buffer = nexus_malloc(sizeof(struct crypto_buffer));

    crypto_buffer->untrusted_addr = untrusted_addr;
    crypto_buffer->size           = size;

    return crypto_buffer;
}

struct crypto_buffer *
crypto_buffer_new(size_t size)
{
    struct crypto_buffer * crypto_buffer = NULL;

    void * untrusted_addr = NULL;

    int err = -1;


    err = ocall_calloc(&untrusted_addr,
                       sizeof(struct metadata_header) + size);

    if (err) {
        return NULL;
    }

    crypto_buffer = crypto_buffer_alloc(untrusted_addr, size);
    if (crypto_buffer == NULL) {
        ocall_free(untrusted_addr);
        ocall_debug("allocating crypto_buffer failed");
    }

    return crypto_buffer;
}

void
crypto_buffer_free(struct crypto_buffer * crypto_buffer)
{
    if (!crypto_buffer) {
        return;
    }

    ocall_free(crypto_buffer->untrusted_addr);

    // as it stands, the crypto_buffer is either allocated inside the enclave
    // or outside within ocall_metadata_get
    //
    if (sgx_is_within_enclave(crypto_buffer, sizeof(struct crypto_buffer))) {
        free(crypto_buffer);
    } else {
        ocall_free(crypto_buffer);
    }
}

void *
crypto_buffer_read(struct crypto_buffer * crypto_buffer, crypto_mac_t * mac)
{
    uint8_t * decrypted_buffer = NULL;
    uint8_t * encrypted_buffer = NULL;

    struct metadata_header metadata_header = { 0 };

    int ret = -1;


    // copy in the the static data and set the encrypted_buffer_ptr 

    memcpy(&metadata_header,
           crypto_buffer->untrusted_addr,
           sizeof(struct metadata_header));

    encrypted_buffer
        = crypto_buffer->untrusted_addr + sizeof(struct metadata_header);



    // allocate buffer and decrypt the contents
    decrypted_buffer = nexus_malloc(metadata_header.info.buffer_size);

    ret = crypto_decrypt(&metadata_header.crypto_context,
                         metadata_header.info.buffer_size,
                         encrypted_buffer,
                         decrypted_buffer,
                         mac,
                         (uint8_t *)&metadata_header.info,
                         sizeof(struct metadata_info));

    if (ret) {
        ocall_debug("crypto_decrypt FAILED");
        goto out;
    }


    ret = 0;
out:
    if (ret) {
        if (decrypted_buffer) {
            free(decrypted_buffer);
        }

        return NULL;
    }

    return decrypted_buffer;
}

int
crypto_buffer_write(struct crypto_buffer * crypto_buffer,
                    struct nexus_uuid    * uuid,
                    uint8_t              * serialized_buffer,
                    size_t                 serialized_buflen,
                    crypto_mac_t         * mac)
{
    struct metadata_header metadata_header = { 0 };

    uint8_t * untrusted_dest_ptr = NULL;

    int ret = -1;


    untrusted_dest_ptr
        = crypto_buffer->untrusted_addr + sizeof(struct metadata_header);

    // initialize the header and perform the encryption
    // 
    // TODO how to keep track of the version ?
    metadata_header.info.buffer_size = serialized_buflen;
    nexus_uuid_copy(uuid, &metadata_header.info.my_uuid);

    ret = crypto_encrypt(&metadata_header.crypto_context,
                         serialized_buflen,
                         serialized_buffer,
                         untrusted_dest_ptr,
                         mac,
                         (uint8_t *)&metadata_header.info,
                         sizeof(struct metadata_info));

    if (ret) {
        ocall_debug("crypto_encrypt() FAILED");
        return -1;
    }

    // copy the metadata header
    memcpy(crypto_buffer->untrusted_addr,
           &metadata_header,
           sizeof(struct metadata_header));

    return 0;
}
