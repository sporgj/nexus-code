#include <stdint.h>
#include <uuid/uuid.h>

#include <nexus_uuid.h>
#include <base58.h>
#include <nexus_util.h>
#include <nexus_log.h>


int
nexus_generate_uuid(struct nexus_uuid * uuid)
{    
    uuid_generate(uuid->raw);

    return 0;
}


char *
nexus_uuid_to_string(struct nexus_uuid * uuid)
{
    char   * uuid_str = NULL;
    size_t   size     = base58_encoded_size(NEXUS_UUID_SIZE);

    uuid_str = (char *)calloc(1, size);

    if (uuid_str == NULL) {
        log_error("Could not allocate buffer for uuid string");
        return NULL;
    }

    base58_encode((uint8_t *)uuid_str, (uint8_t *)uuid, NEXUS_UUID_SIZE);

    return uuid_str;
}
