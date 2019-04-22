#include "abac_types.h"

#include "value.h"

#include "../libnexus_trusted/nexus_str.h"
#include "../libnexus_trusted/rapidstring.h"


struct atom_argument {
    struct abac_value         * abac_value;
};


struct policy_atom *
policy_atom_new();

struct policy_atom *
policy_atom_new_from_predicate(char * predicate);

void
policy_atom_free(struct policy_atom * atom);

size_t
policy_atom_buf_size(struct policy_atom * atom);

char *
policy_atom_to_str(struct policy_atom * atom, bool as_rule);

uint8_t *
policy_atom_to_buf(struct policy_atom * atom, uint8_t * buffer, size_t buflen);

struct policy_atom *
policy_atom_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_ptr);

int
policy_atom_push_arg(struct policy_atom * atom, struct abac_value * abac_value);

const struct atom_argument *
policy_atom_get_arg(struct policy_atom * atom, size_t index);

void
policy_atom_set_predicate(struct policy_atom * atom, char * predicate_str);

bool
policy_atom_is_valid(struct policy_atom * atom);

int
__policy_atom_to_str(struct policy_atom * atom, bool as_rule, rapidstring * string_builder);


// converts what ever type stored in the argument to a string value
char *
atom_argument_string_val(const struct atom_argument * atom_arg);
