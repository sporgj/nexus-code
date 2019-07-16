#include "abac_types.h"


static struct {
    perm_type_t   perm_type;
    const char  * perm_str;
} __perm_map[] = {
    { PERM_READ,        "read" },
    { PERM_WRITE,       "write" },
    { PERM_CREATE,      "create" },
    { PERM_DELETE,      "delete" },
    { PERM_AUDIT,       "audit" },
    { PERM_UNK,         NULL },
};

perm_type_t
perm_type_from_string(char * str)
{
    for (size_t i = 0; __perm_map[i].perm_type != PERM_UNK; i++) {
        if (strncmp(__perm_map[i].perm_str, str, 32) == 0) {
            return __perm_map[i].perm_type;
        }
    }

    return PERM_UNK;
}

char *
perm_type_to_string(perm_type_t perm_type)
{
    for (size_t i = 0; __perm_map[i].perm_type != PERM_UNK; i++) {
        if (__perm_map[i].perm_type == perm_type) {
            return strndup(__perm_map[i].perm_str, 32);
        }
    }

    return NULL;
}
