#pragma once

#include "../libnexus_trusted/nexus_uuid.h"
#include "../libnexus_trusted/nexus_list.h"

#define ATTRIBUTE_NAME_MAX      32
#define ATTRIBUTE_VALUE_SIZE    64

#define SYSTEM_FUNC_MAX_LENGTH  32

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif


typedef enum {
    PERM_READ = 0x01,
    PERM_WRITE,
    PERM_ADMIN,
} perm_type_t;

typedef enum {
    POLICY_ATOM_USER = 0x01,
    POLICY_ATOM_OBJECT,
} atom_type_t;

typedef enum {
    PREDICATE_ATTR = 0x01,      // system attribute
    PREDICATE_FUNC,             // system function
} pred_type_t;

typedef enum {
    USER_ATTRIBUTE_TYPE = 0x01,
    OBJECT_ATTRIBUTE_TYPE
} attribute_type_t;

struct attribute_term {
    struct list_head         list_entry;
    attribute_type_t         type;
    char                     name[ATTRIBUTE_NAME_MAX];
    struct nexus_uuid        uuid;
};


struct policy_atom {
    atom_type_t             atom_type;
    pred_type_t             pred_type;

    struct nexus_uuid       attr_uuid; // 0s when not an attribute
    char                    predicate[SYSTEM_FUNC_MAX_LENGTH];

    size_t                  arity;

    struct nexus_list       args; // list of strings
};


/// comprises of a permission (head), and a list of atoms
struct policy_rule {
    perm_type_t             perm_type;

    size_t                  atom_count;

    struct nexus_uuid       rule_uuid;

    struct nexus_list       atoms;
};

