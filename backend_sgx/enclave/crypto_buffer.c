#include "internal.h"




/* Crypto buffer serialized format */
/* 
   uint32_t magic;   // This should be used to determine which crypto algo's we're using and what the size of the crypto_ctx is... 
   crypto_ctx;       // Contains the sealed crypto information
   uint32_t version; // Version of the data 
   Data
*/

struct nexus_crypto_buf {    
    struct nexus_crypto_ctx crypto_ctx;    
    uint32_t                version;

    size_t    size;
    
    uint8_t * untrusted_addr;
    size_t    untrusted_size;

    uint8_t * trusted_addr;

};



static int
__get_header_len(uint32_t magic)
{
    switch (magic) {

	default:
	    log_error("Invalid magic value\n");
	    return -1;
    }

    return -1;
}


static int
__parse_header(struct nexus_crypto_buf * buf)
{
    uint32_t magic = 0;
    
    if (buf->untrusted_addr == NULL) {
	log_error("Tried to parse header of nexus_crypto_buf with no untrusted_addr\n");
	return -1;
    }

    magic = *(uint32_t *)(buf->untrusted_addr);
    

    /* Check magic against a version */
    switch (magic) {

	// case xxx:
	// Deserialize the crypto context based on this value
	
	default:
	    log_error("Invalid magic value in crypto buffer\n");
	    return -1;
    }

    return 0;
}

static int
__serialize_header(struct nexus_crypto_buf * buf)
{
    /* Serialize the header to the start of the untrusted buffer */

    return -1;
}


struct nexus_crypto_buf *
nexus_crypto_buf_alloc(void   * untrusted_addr,
		       size_t   size)
{
    struct nexus_crypto_buf * buf = NULL;

    buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    buf->size           = size;
    buf->untrusted_addr = untrusted_addr;
    buf->truested_addr  = NULL;

    return nexus_crypto_buf;
}


struct nexus_crypto_buf *
nexus_crypto_buf_new(size_t size)
{
    struct nexus_crypto_buf * buf = NULL;

    buf = nexus_malloc(sizeof(struct nexus_crypto_buf));

    buf->untrusted_addr = NULL;
    buf->truested_addr  = NULL;
    buf->size           = size;
    
    return buf;
}

void
nexus_crypto_buf_free(struct nexus_crypto_buf * buf)
{
    assert(buf != NULL);
    
    if (buf->untrusted_addr) {
	ocall_put(buf->untrusted_addr);
    }

    if (buf->trusted_addr) {
	nexus_free(buf->trusted_addr);
    }
    
    nexus_free(buf);
}

void *
nexus_crypto_buf_get(struct nexus_crypto_buf * buf,
		     struct nexus_mac        * mac)
{

    /* If its already there, just return it */
    if (buf->trusted_addr != NULL) {
	return buf->trusted_addr;
    }
    
    /* Allocate trusted memory */
    buf->trusted_addr = nexus_malloc(buf->size);
    


    
    /* Check if there is an untrusted buf we need to decrypt. If so, copy in and decrypt. */    
    if (buf->untrusted_addr != NULL) {    
	void * sealed_ctx     = buf->untrusted_addr;

#define JRL_CRYPTO_CTX_SIZE (64) /* This needs to be determined dynamically */

	void * untrusted_data = buf->untrusted_addr + JRL_CRYPTO_CTX_SIZE;

	
	uint8_t WTF_IS_AN_AAD;


	/* Unseal the crypto_ctx */


	/* Decrypt the buffer */

	/* Check MAC ? */
	
    }

    return buf->trusted_addr;
    
err:
    
    nexus_free(buf->trusted_addr);
    
    return NULL;
}

int
nexus_crypto_buf_put(struct nexus_crypto_buf * buf,
		     struct nexus_mac        * mac)
{

    if (buf->untrusted_addr == NULL) {
	// Allocate untrusted buffer space (buf->size + header_len)
    }


    __serialize_header(buf);

    /* Encrypt trusted buffer to untrusted buffer after the header */
    
    
    return -1;
}
