#include <stdint.h>
#include <uuid/uuid.h>

#include <nexus_uuid.h>
#include <nexus_encode.h>
#include <nexus_util.h>
#include <nexus_log.h>


int
nexus_uuid_gen(struct nexus_uuid * uuid)
{    
    uuid_generate(uuid->raw);

    return 0;
}


char *
nexus_uuid_to_base64(struct nexus_uuid * uuid)
{
    char * base64_str = NULL;

    base64_str = nexus_base64_encode(uuid->raw, NEXUS_UUID_SIZE);

    return base64_str;
}



int
nexus_uuid_from_base64(struct nexus_uuid * uuid,
		       char              * base64_str)
{
    uint8_t  * tmp_buf = NULL;
    uint32_t   size    = 0;

    int ret = 0;

    
    ret = nexus_base64_decode(base64_str, &tmp_buf, &size);

    if (ret == -1) {
	log_error("Could not decode uuid from (%s)\n", base64_str);
	return -1;
    }
	   
    
    if (size != NEXUS_UUID_SIZE) {
	log_error("Decoded a UUID with invalid length (%d)\n", size);
	return -1;
    }

    memcpy(uuid->raw, tmp_buf, NEXUS_UUID_SIZE);

    nexus_free(tmp_buf);
    
    return 0;
}


char *
nexus_uuid_to_alt64(struct nexus_uuid * uuid)
{
    char * alt64_str = NULL;

    alt64_str = nexus_alt64_encode(uuid->raw, NEXUS_UUID_SIZE);

    return alt64_str;
}



int
nexus_uuid_from_alt64(struct nexus_uuid * uuid,
		      char              * alt64_str)
{
    uint8_t  * tmp_buf = 0;
    uint32_t   size    = 0;

    int ret = 0;
    
    ret = nexus_alt64_decode(alt64_str, &tmp_buf, &size);

    if (ret == -1) {
	log_error("Could not decode uuid from (%s)\n", alt64_str);
	return -1;
    }
	   
    
    if (size != NEXUS_UUID_SIZE) {
	log_error("Decoded a UUID with invalid length (%d)\n", size);
	return -1;
    }

    memcpy(uuid->raw, tmp_buf, NEXUS_UUID_SIZE);

    nexus_free(tmp_buf);
    
    return 0;
}