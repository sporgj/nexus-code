#pragma once

#include "../libnexus_trusted/nexus_log.h"
#include "../libnexus_trusted/nexus_uuid.h"
#include "../libnexus_trusted/nexus_util.h"
#include "../libnexus_trusted/nexus_mac.h"
#include "../libnexus_trusted/hashmap.h"

#include "../crypto_buffer.h"
#include "../metadata.h"

#include "abac_types.h"

extern struct nexus_supernode * global_supernode;


/// returns the attribute store
struct attribute_store *
abac_global_attribute_store();

int
abac_global_export_macversion(struct mac_and_version * macversion);
