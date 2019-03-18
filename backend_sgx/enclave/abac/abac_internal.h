#pragma once

#include "../libnexus_trusted/nexus_log.h"
#include "../libnexus_trusted/nexus_uuid.h"
#include "../libnexus_trusted/nexus_util.h"
#include "../libnexus_trusted/nexus_mac.h"
#include "../libnexus_trusted/hashmap.h"

#include "../metadata.h"


typedef enum {
    PERM_READ = 0x01,
    PERM_WRITE,
    PERM_ADMIN,
} perm_type_t;

typedef enum {
    POLICY_ATOM_USER,
    POLICY_ATOM_OBJECT,
} atom_type_t;

typedef enum {
    PREDICATE_ATTR,   // system attribute
    PREDICATE_FUNC,   // system function
} pred_type_t;


#define ATTRIBUTE_NAME_MAX      32
#define ATTRIBUTE_VALUE_SIZE    64

#define SYSTEM_FUNC_MAX_LENGTH  32

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif



/// returns the attribute store
struct attribute_store *
abac_global_attribute_store();

int
abac_global_export_macversion(struct mac_and_version_t * macversion);
