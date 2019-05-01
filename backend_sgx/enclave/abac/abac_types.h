#pragma once

#include <string.h>

#include "../libnexus_trusted/nexus_uuid.h"
#include "../libnexus_trusted/nexus_list.h"

#define ATTRIBUTE_NAME_MAX      (32)
#define ATTRIBUTE_VALUE_SIZE    (64)

#define NEXUS_POLICY_MAXLEN     (256)

#define SYSTEM_FUNC_MAX_LENGTH  (ATTRIBUTE_NAME_MAX)

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif


typedef enum {
    PERM_READ = 0x01,
    PERM_WRITE,
} perm_type_t;

typedef enum {
    ATOM_TYPE_NONE          = 0x0000,
    ATOM_TYPE_USER          = 0x0001,
    ATOM_TYPE_OBJECT        = 0x0002,

    ATOM_TYPE_ALL           = ATOM_TYPE_USER | ATOM_TYPE_OBJECT,
} atom_type_t;

typedef enum {
    PREDICATE_ATTR = 0x01,      // system attribute
    PREDICATE_FUNC,             // system function
    PREDICATE_BOOL,             // boolean operator
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

struct name_value_pair {
    char name[ATTRIBUTE_NAME_MAX];
    char * value;
};


struct policy_atom {
    atom_type_t             atom_type;
    pred_type_t             pred_type;

    struct nexus_uuid       attr_uuid; // 0s when not an attribute
    char                    predicate[SYSTEM_FUNC_MAX_LENGTH];

    size_t                  arity;

    size_t                  args_bufsize;

    struct nexus_list       args_list; // list of strings
};


/// comprises of a permission (head), and a list of atoms
struct policy_rule {
    perm_type_t             perm_type;

    size_t                  atom_count;

    atom_type_t             atom_types;

    struct nexus_uuid       rule_uuid;

    struct nexus_list       atoms;
};


/// system function are built-in operations on users and objects that return strings
typedef enum {
    USER_FUNCTION = 1,
    OBJECT_FUNCTION
} sys_func_type_t;


static inline atom_type_t
atom_type_from_char(char c)
{
    if (c == 'u') {
        return ATOM_TYPE_USER;
    } else if (c == 'o') {
        return ATOM_TYPE_OBJECT;
    }

    return ATOM_TYPE_NONE;
}

static inline char *
perm_type_to_string(perm_type_t perm_type)
{
    switch (perm_type) {
    case PERM_READ:
        return strndup("read", 5);
    case PERM_WRITE:
        return strndup("write", 6);
    }

    return NULL;
}
