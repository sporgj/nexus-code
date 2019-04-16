#include "abac_types.h"

#include "../libnexus_trusted/rapidstring.h"


/* policy rule stuff */

struct policy_rule *
policy_rule_new(perm_type_t permission);

struct policy_rule *
policy_rule_new_from_perm_str(char * permission_str);

void
policy_rule_free(struct policy_rule * rule);

char *
policy_rule_datalog_string(struct policy_rule * rule);

int
__policy_rule_datalog_string(struct policy_rule * rule, rapidstring * string_builder);

int
policy_rule_push_atom(struct policy_rule * policy_rule, struct policy_atom * atom);

size_t
policy_rule_buf_size(struct policy_rule * rule);

uint8_t *
policy_rule_to_buf(struct policy_rule * rule, uint8_t * buffer, size_t buflen);

struct policy_rule *
policy_rule_from_buf(uint8_t * buffer, size_t buflen, uint8_t ** output_dest_ptr);



/* policy atom */

struct policy_atom *
policy_atom_new();

struct policy_atom *
policy_atom_new_from_predicate(char * predicate);

void
policy_atom_free(struct policy_atom * atom);

size_t
policy_atom_buf_size(struct policy_atom * atom);

char *
policy_atom_to_str(struct policy_atom * atom);

int
policy_atom_push_arg(struct policy_atom * atom, char * str);

void
policy_atom_set_predicate(struct policy_atom * atom, char * predicate_str);

bool
policy_atom_is_valid(struct policy_atom * atom);
