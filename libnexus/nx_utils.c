#include <uuid/uuid.h>

#include "nx_untrusted.h"

void generate_uuid(struct uuid * uuid)
{
    // XXX this might leak info about the MAC & generation time
    uuid_generate_time(uuid->bytes);
}
