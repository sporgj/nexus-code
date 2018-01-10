#include "internal.h"



typedef enum {
    MAGIC_GCM_128 = 0x0001 // GCM 128 bits key
} crypto_buf_magic_t;


/* Crypto buffer serialized format */
/*
   uint32_t magic;   // to determine which algorithm to use
   uint32_t version; // Version of the data
   uint32_t size;    // size of the encrypted buffer

   crypto_ctx;       // Contains the sealed crypto information
   
   Data
*/

struct crypto_buf_info {
    crypto_buf_magic_t magic;

    uint32_t version;

    uint32_t size; // size of the encrypted buffer
} __attribute__((packed));



struct nexus_crypto_buf {
    struct crypto_buf_info  info;
    struct nexus_crypto_ctx crypto_ctx;

    uint8_t * untrusted_addr;
    size_t    untrusted_size;

    uint8_t * trusted_addr;
    size_t    trusted_size;
};



static int
__get_header_len(struct nexus_crypto_buf * crypto_buf)
{
    struct nexus_crypto_ctx * crypto_ctx = &crypto_buf->crypto_ctx;

    switch (crypto_buf->info.magic) {
    case MAGIC_GCM_128:
        return (sizeof(struct crypto_buf_info)
                + nexus_key_buflen(&crypto_ctx->key)
                + nexus_key_buflen(&crypto_ctx->iv)
                + sizeof(struct nexus_mac));

    default:
        log_error("Invalid magic value\n");
        return -1;
    }

    return -1;
}

static int
__parse_gcm128_context(struct nexus_crypto_buf  * crypto_buf,
                       uint8_t                  * untrusted_crypto_ctx_ptr)
{
    struct nexus_crypto_ctx * crypto_ctx = NULL;

    size_t buflen_size = 0;

    int ret = -1;


    // adjust for the info section
    buflen_size = crypto_buf->untrusted_size - sizeof(struct crypto_buf_info);



    crypto_ctx = &crypto_buf->crypto_ctx;

    nexus_init_key(&crypto_ctx->key, NEXUS_RAW_128_KEY);
    nexus_init_key(&crypto_ctx->iv, NEXUS_RAW_128_KEY);
    
    {
        size_t crypto_ctx_size = 0;

	// EKEY
        ret = nexus_key_from_buffer(&crypto_ctx->key,
                                    untrusted_crypto_ctx_ptr,
                                    buflen_size);

        if (ret) {
	    ocall_debug("parsing crypto_ctx key FAILED\n");
	    goto out;
	}

        crypto_ctx_size += nexus_key_buflen(&crypto_ctx->key);
	buflen_size -= crypto_ctx_size;


	// IV
        ret = nexus_key_from_buffer(&crypto_ctx->iv,
                                    untrusted_crypto_ctx_ptr + crypto_ctx_size,
				    buflen_size);

        if (ret) {
	    nexus_key_free(&crypto_ctx->key);
	    ocall_debug("parsing crypto_ctx key FAILED\n");
	    goto out;
	}

        crypto_ctx_size += nexus_key_buflen(&crypto_ctx->iv);
	buflen_size -= crypto_ctx_size;


	// MAC
        memcpy(&crypto_ctx->mac,
               crypto_buf->untrusted_addr + crypto_ctx_size,
               sizeof(struct nexus_mac));
    }

    ret = 0;
out:
    return ret;
}

static int
__parse_header(struct nexus_crypto_buf * crypto_buf)
{
    if (crypto_buf->untrusted_addr == NULL) {
        log_error("Tried to parse header of nexus_crypto_buf with no "
                  "untrusted_addr\n");
        return -1;
    }

    // copy in the info section
    memcpy(&crypto_buf->info,
           crypto_buf->untrusted_addr,
           sizeof(struct crypto_buf_info));


    switch (crypto_buf->info.magic) {
    case MAGIC_GCM_128:
        return __parse_gcm128_context(crypto_buf,
                                      crypto_buf->untrusted_addr
                                          + sizeof(struct crypto_buf_info));

    default:
        log_error("Invalid magic value in crypto buffer\n");
        return -1;
    }

    return 0;
}

struct nexus_crypto_buf *
nexus_crypto_buf_alloc(void   * untrusted_addr,
                       size_t   untrusted_size)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    crypto_buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    crypto_buf->untrusted_addr = untrusted_addr;
    crypto_buf->untrusted_size = untrusted_size;

    return crypto_buf;
}


struct nexus_crypto_buf *
nexus_crypto_buf_new(size_t size)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    int err = -1;


    // by default we perform 128 bit GCM
    crypto_buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    crypto_buf->trusted_addr = NULL;
    crypto_buf->trusted_size = size;

    // allocate the untrusted buffer
    err = ocall_calloc((void **) &crypto_buf->untrusted_addr,
                       size + __get_header_len(crypto_buf));

    if (err) {
        ocall_debug("could not allocate space for crypto_buffer");
        nexus_free(crypto_buf);
        return NULL;
    }

    return crypto_buf;
}

void
nexus_crypto_buf_free(struct nexus_crypto_buf * crypto_buf)
{
    assert(crypto_buf != NULL);

    if (crypto_buf->untrusted_addr) {
        ocall_free(crypto_buf->untrusted_addr);
    }

    nexus_free(crypto_buf);
}

void *
nexus_crypto_buf_get(struct nexus_crypto_buf * crypto_buf,
                     struct nexus_mac        * mac)
{

    /* If its already there, just return it */
    if (crypto_buf->trusted_addr != NULL) {
        return crypto_buf->trusted_addr;
    }

    if (crypto_buf->untrusted_addr == NULL) {
        return NULL;
    }

    /* Allocate trusted memory */
    crypto_buf->trusted_addr = nexus_malloc(crypto_buf->info.size);


    /* Check if there is an untrusted buf we need to decrypt. */
    void * encrypted_data_ptr = NULL;

    int ret = -1;
    

    ret = __parse_header(crypto_buf);
    if (ret) {
        ocall_debug("parsing crypto_buf header FAILED\n");
        goto err;
    }

    /* Unseal the crypto_ctx */
#if 0
    ret = crypto_keyunwrap(global_volumekey, &crypto_buf->crypto_ctx.key);
    if (ret) {
        ocall_debug("crypto_keyunwrap FAILED\n");
        goto err;
    }
#endif

    encrypted_data_ptr
        = crypto_buf->untrusted_addr + __get_header_len(crypto_buf);

    /* Decrypt the buffer */
    ret = crypto_gcm_decrypt(&crypto_buf->crypto_ctx,
                             crypto_buf->trusted_size,
                             encrypted_data_ptr,
                             crypto_buf->trusted_addr,
                             mac,
                             (uint8_t *)&crypto_buf->info,
                             sizeof(struct crypto_buf_info));

    if (ret) {
        ocall_debug("crypto_gcm_decrypt() FAILED\n");
        goto err;
    }

    return crypto_buf->trusted_addr;

err:

    nexus_free(crypto_buf->trusted_addr);

    return NULL;
}

static int
__serialize_gcm128_header(struct nexus_crypto_buf * crypto_buf,
                          uint8_t                 * untrusted_crypto_ctx_ptr)
{
    size_t buflen_size = 0;

    int ret = -1;


    // write out the info into the buffer

    buflen_size = crypto_buf->untrusted_size - sizeof(struct crypto_buf_info);


    // serialize the crypto context
    {
        struct nexus_crypto_ctx * crypto_ctx      = &crypto_buf->crypto_ctx;
        size_t                    crypto_ctx_size = 0;

        // EKEY
        ret = nexus_key_to_buffer(&crypto_ctx->key,
                                  untrusted_crypto_ctx_ptr + crypto_ctx_size,
                                  buflen_size);

        if (ret) {
	    ocall_debug("parsing crypto_ctx key FAILED\n");
	    goto out;
	}

        crypto_ctx_size += nexus_key_buflen(&crypto_ctx->key);
	buflen_size -= crypto_ctx_size;


	// IV
        ret = nexus_key_to_buffer(&crypto_ctx->iv,
				  untrusted_crypto_ctx_ptr + crypto_ctx_size,
				  buflen_size);

        if (ret) {
	    nexus_key_free(&crypto_ctx->key);
	    ocall_debug("parsing crypto_ctx key FAILED\n");
	    goto out;
	}

        crypto_ctx_size += nexus_key_buflen(&crypto_ctx->iv);
	buflen_size -= crypto_ctx_size;


	// MAC
        memcpy(crypto_buf->untrusted_addr + crypto_ctx_size,
               &crypto_ctx->mac,
               sizeof(struct nexus_mac));
    }

    ret = 0;
out:
    return ret;
}

static int
__serialize_header(struct nexus_crypto_buf * crypto_buf)
{
    memcpy(crypto_buf->untrusted_addr,
           &crypto_buf->info,
           sizeof(struct crypto_buf_info));

    /* Check magic against a version */
    switch (crypto_buf->info.magic) {
    case MAGIC_GCM_128:
        return __serialize_gcm128_header(crypto_buf,
                                         crypto_buf->untrusted_addr
                                             + sizeof(struct crypto_buf_info));

    default:
        log_error("Invalid magic value in crypto buffer\n");
        return -1;
    }

    return -1;
}

int
nexus_crypto_buf_put(struct nexus_crypto_buf * crypto_buf,
                     uint8_t                 * trusted_buf,
                     struct nexus_mac        * mac)
{
    uint8_t * encrypted_buffer_ptr = NULL;

    size_t header_len = 0;

    int ret = -1;


    header_len = __get_header_len(crypto_buf);


    if (crypto_buf->untrusted_addr == NULL) {
        int err = ocall_calloc((void **)&crypto_buf->untrusted_addr,
                               crypto_buf->trusted_size + header_len);

        if (err) {
            ocall_debug("could not allocate space for crypto_buffer");
            nexus_free(crypto_buf);
            return -1;
        }
    }


    // adjust the crypto info. This is used as additional authentication
    // material when encrypting the trusted buffer
    crypto_buf->info.magic = MAGIC_GCM_128;
    crypto_buf->info.size  = crypto_buf->trusted_size;

    // encrypt the data
    crypto_buf->trusted_addr = trusted_buf;

    ret = crypto_gcm_encrypt(&crypto_buf->crypto_ctx,
                             crypto_buf->trusted_size,
                             crypto_buf->trusted_addr,
                             crypto_buf->untrusted_addr + header_len,
                             mac,
                             (uint8_t *)&crypto_buf->info,
                             sizeof(struct crypto_buf_info));


    // TODO keywrap the crypto context


    // write the info + crypto_context to the buffer
    ret = __serialize_header(crypto_buf);
    if (ret) {
        ocall_debug("serializing header FAILED \n");
        return -1;
    }

    return 0;
}
