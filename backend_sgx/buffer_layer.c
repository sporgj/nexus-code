#include "internal.h"

void
nexus_rawbuf_free(struct raw_buffer * raw_buffer)
{
    nexus_free(raw_buffer->untrusted_addr);
    nexus_free(raw_buffer);
}
