#include "internal.h"



#define NEXUS_MAGIC_V1 0x6e780001   



/* Crypto buffer serialized format */
/*
   uint32_t magic;   // to determine which algorithm to use
   uint32_t version; // Version of the data
   uint32_t size;    // size of the encrypted buffer

   crypto_ctx;       // Contains the sealed crypto information

   Data
*/


// ---- GCM stuff ----
#define GCM128_KEY_SIZE (16)
#define GCM128_IV_SIZE  (16)

struct __gcm_header {
    uint8_t key[GCM128_KEY_SIZE];
    uint8_t  iv[GCM128_IV_SIZE];    
    uint8_t mac[NEXUS_MAC_SIZE];
} __attribute__((packed));


struct crypto_buf_hdr {
    uint32_t magic;

    uint32_t version;

    uint32_t size; // size of the encrypted buffer

    struct __gcm_header gcm_hdr;
} __attribute__((packed));






struct nexus_crypto_buf {
    struct nexus_crypto_ctx crypto_ctx;

    uint32_t version;

    struct nexus_uuid uuid;

    // for managing the external buffer
    uint8_t * external_addr;
    size_t    external_size;

    uint8_t * internal_addr;
    size_t    internal_size;
};





struct nexus_crypto_buf *
nexus_crypto_buf_new(size_t size)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    crypto_buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    crypto_buf->internal_addr = nexus_malloc(size);
    crypto_buf->internal_size = size;

    return crypto_buf;
}

struct nexus_crypto_buf *
nexus_crypto_buf_create(struct nexus_uuid * buf_uuid)
{
    struct nexus_crypto_buf * crypto_buf = NULL;

    void   * external_addr = NULL;
    size_t   external_size = 0;
	
    external_addr = bufer_layer_get(buf_uuid, &external_size);
	
    if (external_addr == NULL) {
	log_error("Could not retrieve external addr for buffer\n");
	return NULL;
    }

    crypto_buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    nexus_uuid_copy(buf_uuid, &(crypto_buf->uuid));

    crypto_buf->external_addr = external_addr;
    crypto_buf->external_size = external_size;
    
    return crypto_buf;
}

void
nexus_crypto_buf_free(struct nexus_crypto_buf * crypto_buf)
{
    assert(crypto_buf != NULL);

    if (crypto_buf->external_addr) {
        buffer_layer_put(&(crypto_buf->uuid));
    }


    // free the crypto context
    {
        struct nexus_crypto_ctx * crypto_context = &(crypto_buf->crypto_ctx);
	nexus_crypto_ctx_free(crypto_context);
    }

    nexus_free(crypto_buf);
}

static int
__parse_gcm128_context(struct nexus_crypto_buf  * crypto_buf,
		       struct crypto_buf_hdr    * buf_hdr)
{
    struct nexus_crypto_ctx * crypto_ctx = &(crypto_buf->crypto_ctx);
    
    struct nexus_key wrapped_key;

    int ret = -1;
    
    ret = __nexus_key_from_buf(&wrapped_key, NEXUS_WRAPPED_128_KEY, buf_hdr->gcm_hdr.key, GCM128_KEY_SIZE);

    if (ret == -1) {
	log_error("Error retrieving wrapped key from GCM header\n");
	goto err;
    }
    
    ret = __nexus_derive_key(&crypto_ctx->key, NEXUS_RAW_128_KEY, &wrapped_key);
    nexus_free_key(&wrapped_key);
    
    if (ret == -1) {
        log_error("Error Deriving key from GCM header\n");
        goto err;
    }
   

    // IV
    ret = __nexus_key_from_buf(&crypto_ctx->iv, NEXUS_RAW_128_KEY, buf_hdr->gcm_hdr.iv, GCM128_IV_SIZE);

    if (ret == -1) {
	log_error("Could not retrieve IV from GCM header\n");
	goto err;
    }
        
    // MAC
    ret = __nexus_mac_from_buf(&crypto_ctx->mac, buf_hdr->gcm_hdr.mac);

    if (ret == -1) {
	log_error("Could not retrieve MAC from GCM header\n");
	goto err;
    }

    return 0;
    
 err:

    return -1;
}

static int
__get_header_len()
{
      return sizeof(struct crypto_buf_hdr);
}

static int
__parse_header(struct nexus_crypto_buf * crypto_buf)
{
    struct crypto_buf_hdr buf_hdr;

    /* JRL: At the moment this will parse the buffer from untrusted memory
     *      I am not sure whether we need to copy it in first...
     */

    memcpy(&buf_hdr, crypto_buf->external_addr, __get_header_len());
        
    if (buf_hdr.magic != NEXUS_MAGIC_V1) {
	log_error("invalid magic value in crypto_buffer\n");
	return -1;
    }

    if (buf_hdr.size != (crypto_buf->external_size - __get_header_len())) {
	log_error("Size mismatch in crypto_buffer\n");
	return -1;
    }
    
    crypto_buf->version       = buf_hdr.version;
    crypto_buf->internal_size = buf_hdr.size;
    
    return __parse_gcm128_context(crypto_buf, &buf_hdr);
}

void *
nexus_crypto_buf_get(struct nexus_crypto_buf * crypto_buf,
                     struct nexus_mac        * mac)
{
    int ret = -1;

    /* Internal buffer already exists */
    if (crypto_buf->internal_addr != NULL) {
        return crypto_buf->internal_addr;
    }


    
    if (crypto_buf->external_addr == NULL) {
	log_error("Error: Unitialized crypto_buf\n");
	return NULL;
    }

    
    // parses and unwraps the buffer's crypto context
    ret = __parse_header(crypto_buf);
    
    if (ret == -1) {
        log_error("parsing crypto_buf header FAILED\n");
        goto err;
    }

    /* Allocate internal memory */
    crypto_buf->internal_addr = nexus_malloc(crypto_buf->internal_size);

    /* Decrypt the buffer */
    {
        ret = crypto_gcm_decrypt(&crypto_buf->crypto_ctx,
                                 crypto_buf->internal_size,
                                 crypto_buf->external_addr + __get_header_len(),
                                 crypto_buf->internal_addr,
                                 mac,
                                 NULL,
                                 0);

        if (ret) {
            log_error("crypto_gcm_decrypt() FAILED\n");
            goto err;
        }
    }


    return crypto_buf->internal_addr;

 err:
    nexus_free(crypto_buf->internal_addr);

    return NULL;
}

static int
__serialize_gcm128_context(struct nexus_crypto_buf * crypto_buf,
			   struct crypto_buf_hdr   * buf_hdr)
{
    struct nexus_crypto_ctx * crypto_ctx  = &(crypto_buf->crypto_ctx);
    struct nexus_key        * wrapped_key = NULL;

    int       ret = -1;
    uint8_t * ret_ptr = NULL;



    wrapped_key = nexus_derive_key(NEXUS_WRAPPED_128_KEY, &(crypto_ctx->key));
    
    if (wrapped_key == NULL) {
        log_error("could not wrap gcm128 key\n");
        return -1;
    }
 
    // EKEY is sealed in the buffer
    ret_ptr = nexus_key_to_buf(wrapped_key, buf_hdr->gcm_hdr.key, GCM128_KEY_SIZE);
    
    if (ret_ptr == NULL) {
	log_error("Could not serialize wrapped key\n");
	goto err;
    }
    
    // IV
    ret_ptr = nexus_key_to_buf(&(crypto_ctx->iv), buf_hdr->gcm_hdr.iv, GCM128_IV_SIZE);
    
    if (ret_ptr == NULL) {
	log_error("Could not serialize IV\n");
	goto err;
    }
    
    // MAC
    nexus_mac_to_buf(&(crypto_ctx->mac), buf_hdr->gcm_hdr.mac);


    nexus_free_key(wrapped_key);
    nexus_free(wrapped_key);

    return 0;
    
err:
    nexus_free_key(wrapped_key);
    nexus_free(wrapped_key);

    return -1;
}

/**
 * Writes the crypto_context + buf_info into external_addr
 */
static int
__serialize_header(struct nexus_crypto_buf * crypto_buf)
{
    struct crypto_buf_hdr * buf_hdr = NULL;

    int ret = 0;
    

    buf_hdr = (struct crypto_buf_hdr *)(crypto_buf->external_addr);


    buf_hdr->magic   = NEXUS_MAGIC_V1;
    buf_hdr->version = crypto_buf->version;
    buf_hdr->size    = crypto_buf->external_size;    
    
    return __serialize_gcm128_context(crypto_buf, buf_hdr);
}

int
nexus_crypto_buf_put(struct nexus_crypto_buf * crypto_buf,
                     struct nexus_mac        * mac)
{
    int ret = -1;


    // if we have no space allocated...
    if (crypto_buf->external_addr == NULL) {
	struct nexus_uuid buf_uuid;
	
        crypto_buf->external_size = __get_header_len() + crypto_buf->internal_size;
	crypto_buf->external_addr = buffer_layer_alloc(crypto_buf->external_size, &buf_uuid);

        if (crypto_buf->external_addr == NULL) {
            log_error("buffer_layer_alloc FAILED\n");
            return -1;
        }

	nexus_uuid_copy(&buf_uuid, &(crypto_buf->uuid));
    }


    crypto_buf->version += 1;


    ret = crypto_gcm_encrypt(&crypto_buf->crypto_ctx,
                             crypto_buf->internal_size,
                             crypto_buf->internal_addr,
                             crypto_buf->external_addr + __get_header_len(),
                             mac,
                             NULL,
                             0);



    
    // write the info + sealed(crypto_context) to the buffer
    ret = __serialize_header(crypto_buf);

    if (ret) {
	crypto_buf->version -= 1;
        log_error("serializing header FAILED\n");
        return -1;
    }

    return 0;
}
