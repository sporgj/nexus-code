#include "abac_internal.h"


struct policy_store {
    struct nexus_uuid       my_uuid;

    uint32_t                rules_count;

    struct nexus_list       rules_list;
};

struct policy_rule {
    perm_type_t             perm_type;
};


typedef enum {
    POLICY_ATOM_USER;
    POLICY_ATOM_OBJECT;
} atom_type_t;

typedef enum {
    PREDICATE_ATTR;   // system attribute
    PREDICATE_FUNC;   // system function
} pred_type_t;


struct policy_atom {
    atom_type_t             atom_type;
    pred_type_t             pred_type;

    union {
        struct nexus_uuid   attr_uuid;
        char                sys_func[SYSTEM_FUNC_MAX_LENGTH];
    };

    list_head               components;
};
