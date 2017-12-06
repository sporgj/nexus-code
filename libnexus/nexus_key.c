#include <stdlib.h>

#include <mbedtls/pk.h>


#include <nexus_key.h>
#include <nexus_util.h>
#include <nexus_log.h>



struct nexus_key * 
nexus_load_key_from_file(char * key_path)
{
    struct nexus_key * key = NULL;

    int ret = 0;

    key = calloc(sizeof(struct nexus_key), 1);

    if (key == NULL) {
	log_error("Could not allocate nexus_key for file (%s)\n", key_path);
	return NULL;
    }

    ret = mbedtls_pk_load_file(key_path, &(key->data), &(key->key_size));

    if (ret != 0) {
	log_error("Could not load nexus key from file (%s)\n", key_path);
	nexus_free(key);
	return NULL;
    }
    
    return key;
}

void
nexus_free_key(struct nexus_key * key)
{
    nexus_free(key->data);
    nexus_free(key);
}
