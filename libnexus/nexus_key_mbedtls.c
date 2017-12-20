/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <unistd.h>



#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>

#if 0
    /* This makes things take forever, so lets comment this out for now... */
#define DEV_RANDOM_THRESHOLD        32

static int
__mbedtls_entropy_fn(void          * data,
		     unsigned char * output,
		     size_t          len,
		     size_t        * olen )
{
    unsigned char * out_ptr = output;
    FILE          * file    = NULL;

    size_t ret  = 0;
    size_t left = len;

    *olen = 0;

    file = fopen("/dev/random", "rb");

    if (file == NULL) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    
    while (left > 0) {
        /* /dev/random can return much less than requested. If so, try again */
        ret = fread(out_ptr, 1, left, file);

        if ( (ret          == 0) &&
	     (ferror(file) != 0) ) {

            fclose(file);
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }

        out_ptr += ret;
        left    -= ret;

        sleep( 1 );
    }
    
    fclose(file);

    *olen = len;

    return 0;
}
#endif



static char *
__mbedtls_pub_key_to_str(struct nexus_key * key)
{
    unsigned char   out_buf[16000]; // Constant size taken from mbedtls source code...
    char          * out_str = NULL;
    
    int ret = 0;
    
    memset(out_buf, 0, 16000);

    ret = mbedtls_pk_write_pubkey_pem(key->key_state, out_buf, 16000);

    if (ret != 0) {
	log_error("Could not write MBEDTLS PRV key to string\n");
	return NULL;
    }

    ret = asprintf(&out_str, "%s", out_buf);

    if (ret == -1) {
	log_error("Could not create MBEDTLS PRV key string\n");
	return NULL;
    }
    
    return out_str;
}


static char *
__mbedtls_prv_key_to_str(struct nexus_key * key)
{
    unsigned char   out_buf[16000]; // Constant size taken from mbedtls source code...
    char          * out_str = NULL;
    
    int ret = 0;
    
    memset(out_buf, 0, 16000);

    ret = mbedtls_pk_write_key_pem(key->key_state, out_buf, 16000);

    if (ret != 0) {
	log_error("Could not write MBEDTLS PRV key to string\n");
	return NULL;
    }

    ret = asprintf(&out_str, "%s", out_buf);

    if (ret == -1) {
	log_error("Could not create MBEDTLS PRV key string\n");
	return NULL;
    }
    
    return out_str;
}



static int
__mbedtls_prv_key_to_file(struct nexus_key * key,
		      char             * file_path)
{
    char * key_str  = NULL;
    int ret = 0;
    
    key_str = __mbedtls_prv_key_to_str(key);

    if (key_str == NULL) {
	log_error("Could not get key string (type=%s)\n", nexus_key_type_to_str(key->type));
	return -1;
    }

    ret = nexus_write_raw_file(file_path, key_str, strlen(key_str));

    if (ret == -1) {
	log_error("Could not write MBEDTLS private key to file (%s)\n", file_path);
    }

    nexus_free(key_str);
    return ret;
}


static int
__mbedtls_pub_key_to_file(struct nexus_key * key,
			  char             * file_path)
{
    char * key_str  = NULL;

    int ret = 0;
    
    key_str = __mbedtls_pub_key_to_str(key);

    if (key_str == NULL) {
	log_error("Could not get key string (type=%s)\n", nexus_key_type_to_str(key->type));
	return -1;
    }

    ret = nexus_write_raw_file(file_path, key_str, strlen(key_str));

    if (ret == -1) {
	log_error("Could not write MBEDTLS public key to file (%s)\n", file_path);
    }

    nexus_free(key_str);
    return ret;
}


static int
__mbedtls_prv_key_from_str(struct nexus_key * key,
			   char             * key_str)
{
    mbedtls_pk_context * ctx = NULL;

    int ret = 0;
    
    ctx = calloc(sizeof(mbedtls_pk_context), 1);
    
    if (ctx == NULL) {
	log_error("Could not allocate key context\n");
	return -1;
    }

    mbedtls_pk_init(ctx);    

    /* Currently does not support password protected keys... */
    ret = mbedtls_pk_parse_key(ctx, (uint8_t *)key_str, strlen(key_str) + 1, NULL, 0);

    if (ret != 0) {
	log_error("Could not parse private key string (%s)\n", key_str);
	goto err;
    }

    key->key_state = ctx;
    
    nexus_free(key_str);
    return 0;
    
 err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);
    
    return -1;
}


static int
__mbedtls_pub_key_from_str(struct nexus_key * key,
			   char             * key_str)
{
   mbedtls_pk_context * ctx = NULL;

    int ret = 0;
    
    ctx = calloc(sizeof(mbedtls_pk_context), 1);
    
    if (ctx == NULL) {
	log_error("Could not allocate key context\n");
	return -1;
    }

    mbedtls_pk_init(ctx);    

    ret = mbedtls_pk_parse_public_key(ctx, (uint8_t *)key_str, strlen(key_str) + 1);

    if (ret != 0) {
	log_error("Could not parse public key string (%s)\n", key_str);
	goto err;
    }

    key->key_state = ctx;
    
    nexus_free(key_str);
    return 0;
    
 err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);
    
    return -1;
}
			   


static int
__mbedtls_prv_key_from_file(struct nexus_key * key, 
			    char             * file_path)
{
    mbedtls_pk_context * ctx = NULL;

    int ret = 0;
    
    ctx = calloc(sizeof(mbedtls_pk_context), 1);
    
    if (ctx == NULL) {
	log_error("Could not allocate key context\n");
	return -1;
    }

    mbedtls_pk_init(ctx);

    ret = mbedtls_pk_parse_keyfile(ctx, file_path, NULL);

    if (ret != 0) {
	log_error("Could not parse public key file (%s)\n", file_path);
	goto err;
    }

    key->key_state = ctx;
    
    return 0;
    
 err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);
    
    return -1;
}

static int
__mbedtls_pub_key_from_file(struct nexus_key * key, 
			    char             * file_path)
{
    mbedtls_pk_context * ctx = NULL;

    int ret = 0;
    
    ctx = calloc(sizeof(mbedtls_pk_context), 1);
    
    if (ctx == NULL) {
	log_error("Could not allocate key context\n");
	return -1;
    }

    mbedtls_pk_init(ctx);

    ret = mbedtls_pk_parse_public_keyfile(ctx, file_path);

    if (ret != 0) {
	log_error("Could not parse public key PEM string\n");
	goto err;
    }

    key->key_state = ctx;
    
    return 0;
    
 err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);

    return -1;
}





/* Just create a pub key pem string from private key, and parse it into the public key */
static int
__mbedtls_derive_pub_key(struct nexus_key * pub_key,
			 struct nexus_key * prv_key)
{
    char * pem_str = NULL;
    int    ret     = 0;

    pem_str = __mbedtls_pub_key_to_str(prv_key);


    if (pem_str == NULL) {
	log_error("Could not generate public key PEM\n");
	return -1;
    }

    ret = __mbedtls_pub_key_from_str(pub_key, pem_str);

    if (ret == -1) {
	log_error("Could not derive public key from string (%s)\n", pem_str);
    }
    
    nexus_free(pem_str);
    return ret;   
}


/* Generates a 2048 bit RSA private key */
static int
__mbedtls_create_prv_key(struct nexus_key * key)
{
    mbedtls_pk_context      * ctx = NULL;

    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  ctr_drbg;


    int key_size = 2048; 
    int ret      = 0;

    ctx = calloc(sizeof(mbedtls_pk_context), 1);

    if (ctx == NULL) {
	log_error("Could not allocate key context\n");
	return -1;
    }
    
    mbedtls_pk_init      (ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init (&entropy);

#if 0
    /* This makes things take forever, so lets comment this out for now... */
    log_debug("Adding Entropy source\n");
    ret = mbedtls_entropy_add_source(&entropy,
				     __mbedtls_entropy_fn,
				     NULL,
				     DEV_RANDOM_THRESHOLD,
				     MBEDTLS_ENTROPY_SOURCE_STRONG);

    if (ret != 0) {
	log_error("Could not add entropy source (ret = %d)\n", ret);
	goto err;
    }
#endif

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
				mbedtls_entropy_func,
				&entropy,
				NULL,
				0);

    if (ret != 0) {
	log_error("Could not seed random generator (ret = %d)\n", ret);
	goto err;
    }

    ret = mbedtls_pk_setup(ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    if (ret != 0) {
	log_error("Could not setup pk context (ret = %d)\n", ret);
	goto err;
    }
    
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*ctx),
			      mbedtls_ctr_drbg_random,
			      &ctr_drbg,
			      key_size,
			      65537);

    if (ret != 0) {
	log_error("Could not generate RSA private key (ret = %d)\n", ret);
	goto err;
    }

    key->key_state = ctx;
    
    return 0;
    
 err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);
    
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free (&entropy);
    
    return -1;
}
	


static void
__mbedtls_free_key(struct nexus_key * key)
{
    mbedtls_pk_free(key->key_state);
    nexus_free(key->key_state);
}
