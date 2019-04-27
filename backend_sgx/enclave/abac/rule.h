#include <stdbool.h>
#include "abac_types.h"

#include "../libnexus_trusted/rapidstring.h"

#include "./datalog-engine/datalog.h"


int
__permission_type_to_datalog(perm_type_t perm_type, rapidstring * string_builder, bool as_rule);

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

int
policy_rule_to_db(struct policy_rule * rule, dl_db_t db);
