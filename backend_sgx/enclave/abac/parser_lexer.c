#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <nexus_util.h>
#include <nexus_log.h>

#include "abac_internal.h"
#include "rule.h"
#include "atom.h"
#include "value.h"


#define MAX_ARGUMENT_LEN  (256)

typedef enum {
    TOK_UNKNOWN = 0,
    TOK_LPAREN = 1,
    TOK_RPAREN,
    TOK_COMMA,
    TOK_NUMBER,
    TOK_STRING,
    TOK_IDENTIFIER,
    TOK_DOTNOTATION,
    TOK_COLONEQUALS,

    TOK_LT,
    TOK_LE,
    TOK_GT,
    TOK_GE,
    TOK_EE,

    TOK_END,
} token_type_t;

struct my_token {
    token_type_t type;
    char *       val;
    size_t       pos;
};

struct my_lexer {
    char * input; // the input being scanned
    size_t pos;   // current position
};

struct my_parser {
    struct my_lexer * lexer;

    struct my_token * token;
    struct my_token * prev_token;

    struct policy_rule * policy_rule;
};

static void
token_free(struct my_token * tok)
{
    if (tok->val) {
        free(tok->val);
    }

    free(tok);
}

static bool
token_is_boolean_op(struct my_token * token)
{
    switch (token->type) {
    case TOK_LT:
    case TOK_LE:
    case TOK_GT:
    case TOK_GE:
    case TOK_EE:
        return true;
    }

    return false;
}

struct my_lexer *
lexer_create(char * input_str)
{
    struct my_lexer * lexer = nexus_malloc(sizeof(struct my_lexer));

    lexer->input = input_str;
    lexer->pos   = 0;

    return lexer;
}

void
lexer_destroy(struct my_lexer * lexer)
{
    free(lexer);
}

static struct my_token *
__tok(struct my_lexer * lexer, token_type_t t)
{
    struct my_token * token = nexus_malloc(sizeof(struct my_token));

    token->type = t;
    token->pos  = lexer->pos;

    return token;
}

static inline char
__next_char(struct my_lexer * lexer)
{
    char c = lexer->input[lexer->pos];

    if (c) {
        lexer->pos += 1;
        return c;
    }

    return '\0';
}

static void
__backup(struct my_lexer * lexer)
{
    if (lexer->pos > 0) {
        lexer->pos -= 1;
    }
}

struct my_token *
__lex_number(struct my_lexer * lexer)
{
    struct my_token * token = nexus_malloc(sizeof(struct my_token));
    char            * start = &lexer->input[lexer->pos - 1];
    size_t            len   = 1;

    while (1) {
        char c = __next_char(lexer);

        if ((c >= '0' && c <= '9')) {
            len++;
            continue;
        }

        // stop once we reach another token
        __backup(lexer);
        break;
    }

    if (len > MAX_ARGUMENT_LEN) {
        log_error("number length is too large. len=%zu, max=%zu\n", len, MAX_ARGUMENT_LEN);
        return __tok(lexer, TOK_UNKNOWN);
    }

    token      = __tok(lexer, TOK_NUMBER);
    token->val = strndup(start, len);
    token->pos = (lexer->pos - len);

    return token;
}

struct my_token *
__lex_identifier(struct my_lexer * lexer)
{
    struct my_token * token = NULL;
    char *            start = &lexer->input[lexer->pos - 1];
    size_t            len   = 1;

    bool dot_notation = false;
    bool at_notation = (*start == '@');

    while (1) {
        char c = __next_char(lexer);

        if (isalnum(c)) {
            len++;
            continue;
        }

        if (c == '.') {
            if (dot_notation) {
                log_error("duplicate dot found at %zu\n", lexer->pos);
                return __tok(lexer, TOK_UNKNOWN);
            }

            len++;

            dot_notation = true;
            continue;
        }

        if (c == '@') {
            if (at_notation) {
                log_error("duplicate @ found at %zu\n", lexer->pos);
                return __tok(lexer, TOK_UNKNOWN);
            }

            len++;

            at_notation = true;
            continue;
        }

        // stop once we reach another token
        __backup(lexer);
        break;
    }

    if (len > MAX_ARGUMENT_LEN) {
        log_error("identifier length is too large. len=%zu, max=%zu\n", len, MAX_ARGUMENT_LEN);
        return __tok(lexer, TOK_UNKNOWN);
    }

    token      = __tok(lexer, (dot_notation ? TOK_DOTNOTATION : TOK_IDENTIFIER));
    token->val = strndup(start, len);
    token->pos = (lexer->pos - len);

    return token;
}

struct my_token *
__lex_string(struct my_lexer * lexer)
{
    struct my_token * token = NULL;
    char            * start = &lexer->input[lexer->pos];
    size_t            len   = 0;

    while (1) {
        char c = __next_char(lexer);

        if (c == '"') {
            break;
        }

        len++;
    }

    if (len > MAX_ARGUMENT_LEN) {
        log_error("string length is too large. len=%zu, max=%zu\n", len, MAX_ARGUMENT_LEN);
        return __tok(lexer, TOK_UNKNOWN);
    }

    token      = __tok(lexer, TOK_STRING);
    token->val = strndup(start, len);
    token->pos = (lexer->pos - len);

    return token;
}

// XXX: this can be compressed
static struct my_token *
__lex_boolean_op(struct my_lexer * lexer, char curr_char)
{
    char next_char = __next_char(lexer);

    switch (curr_char) {
    case '<':
        if (next_char == '=') {
            return __tok(lexer, TOK_LE);
        } else {
            __backup(lexer);
            return __tok(lexer, TOK_LT);
        }
    case '>':
        if (next_char == '=') {
            return __tok(lexer, TOK_GE);
        } else {
            __backup(lexer);
            return __tok(lexer, TOK_GT);
        }
    case '=':
        if (next_char == '=') {
            return __tok(lexer, TOK_EE);
        } else {
            log_error("unknown character `%c` at pos %zu\n", next_char, lexer->pos - 1);
            return __tok(lexer, TOK_UNKNOWN);
        }
    }

    return __tok(lexer, TOK_UNKNOWN);
}

struct my_token *
lexer_next_token(struct my_lexer * lexer)
{
    struct my_token * token = NULL;
    char              c;
    char              n;

repeat:
    c = __next_char(lexer);
    if (c == '\0') {
        return __tok(lexer, TOK_END);
    }

    switch (c) {
    case ' ':
    case '\t':
        goto repeat;
    case ',':
        return __tok(lexer, TOK_COMMA);
    case '(':
        return __tok(lexer, TOK_LPAREN);
    case ')':
        return __tok(lexer, TOK_RPAREN);
    case '<':
    case '>':
    case '=':
        return __lex_boolean_op(lexer, c);
    case ':':
        n = __next_char(lexer);
        if (n != '-') {
            log_error("expected `:-` at position %zu\n", lexer->pos - 2);
            return __tok(lexer, TOK_UNKNOWN);
        }

        return __tok(lexer, TOK_COLONEQUALS);
    default:
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '@')) {
            return __lex_identifier(lexer);
        } else if (c == '"') {
            return __lex_string(lexer);
        } else if ((c >= '1' && c <= '9')) {
            return __lex_number(lexer);
        }
    }

    log_error("Unknown token `%c` at position %zu\n", c, lexer->pos);

    __backup(lexer);

    return __tok(lexer, TOK_UNKNOWN);
}

struct my_parser *
parser_new(struct my_lexer * lexer)
{
    struct my_parser * parser = nexus_malloc(sizeof(struct my_parser));

    parser->lexer = lexer;

    return parser;
}

void
parser_free(struct my_parser * parser)
{
    if (parser->token) {
        token_free(parser->token);
    }

    free(parser);
}

char *
my_token_to_string(token_type_t type)
{
    switch (type) {
    case TOK_EE:
        return "==";
    case TOK_GT:
        return ">";
    case TOK_LT:
        return "<";
    case TOK_GE:
        return ">=";
    case TOK_LE:
        return "<=";
    case TOK_COMMA:
        return ",";
    case TOK_LPAREN:
        return "(";
    case TOK_RPAREN:
        return ")";
    case TOK_NUMBER:
        return "number";
    case TOK_STRING:
        return "string";
    case TOK_IDENTIFIER:
        return "identifier";
    case TOK_DOTNOTATION:
        return "dotnotation";
    }

    return "(unknown)";
}

// XXX: the parser can only backup once
static void
__prev_token(struct my_parser * parser)
{
    parser->prev_token = parser->token;
    parser->token = NULL;
}

static struct my_token *
__next_token(struct my_parser * parser)
{
    if (parser->prev_token) {
        parser->token = parser->prev_token;
        parser->prev_token = NULL;

        return parser->token;
    }

    if (parser->token) {
        token_free(parser->token);
    }

    parser->token = lexer_next_token(parser->lexer);

    return parser->token;
}

static int
__consume_token(struct my_parser * parser, token_type_t expected_type)
{
    struct my_token * token = __next_token(parser);

    if (token->type != expected_type) {
        log_error("illegal syntax. Position=%zu. "
                  "Expected=`%s`, Got=`%s`.\n",
                  token->pos,
                  my_token_to_string(expected_type),
                  my_token_to_string(token->type));
        return -1;
    }

    return 0;
}

static struct abac_value *
__abac_value_from_token(struct my_token * token)
{
    if (token->type == TOK_DOTNOTATION) {
        return abac_value_from_str(token->val, true);
    } else if (token->type == TOK_STRING) {
        return abac_value_from_str(token->val, false);
    } else if (token->type == TOK_NUMBER) {
        int number = atoi(token->val);
        return abac_value_from_int(number);
    } else {
        log_error("expected dot var/string/number at position=%zu\n", token->pos);
        return NULL;
    }
}

static int
__parse_regular_atom_type(struct my_parser * parser, struct policy_atom * atom)
{
    // parse the atom type u|o
    if (__consume_token(parser, TOK_IDENTIFIER)) {
        log_error("__consume_token() FAILED\n");
        goto out_err;
    }

    {
        struct my_token * tok = parser->token;

        if (strncmp(tok->val, "u", 5) == 0) {
            atom->atom_type = ATOM_TYPE_USER;
        } else if (strncmp(tok->val, "o", 5) == 0) {
            atom->atom_type = ATOM_TYPE_OBJECT;
        } else {
            log_error("unknown atom type\n");
            goto out_err;
        }
    }

    // now get the remaining arguments
    struct my_token * token = __next_token(parser);
    if (token->type == TOK_COMMA) {
        token = __next_token(parser);
        struct abac_value * abac_value = NULL;

        if ((token->type != TOK_STRING) && (token->type == TOK_NUMBER)) {
            log_error("expected string/number at position=%zu\n", token->pos);
            goto out_err;
        }

        abac_value = __abac_value_from_token(token);
        if (policy_atom_push_arg(atom, abac_value)) {
            log_error("policy_atom_push_arg() FAILED\n");
            goto out_err;
        }
    } else if (token->type == TOK_RPAREN) {
        __prev_token(parser);
    } else {
        log_error("unexpeected token at position %zu\n", token->pos);
        goto out_err;
    }

    return 0;
out_err:
    return -1;
}

static int
__parse_boolean_atom_type(struct my_parser * parser, struct policy_atom * atom)
{
    struct my_token * token = __next_token(parser);

    struct abac_value * abac_value = NULL;

    int args_pushed = 0;

push_arg:
    abac_value = __abac_value_from_token(token);

    if (abac_value == NULL) {
        log_error("could not derive abac value\n");
        return -1;
    }

    if (policy_atom_push_arg(atom, abac_value)) {
        abac_value_free(abac_value);
        log_error("policy_atom_push_arg() FAILED\n");
        return -1;
    }

    if (token->type == TOK_DOTNOTATION) {
        if (token->val[0] == 'u') {
            atom->atom_type |= ATOM_TYPE_USER;
        } else if (token->val[0] == 'o') {
            atom->atom_type |= ATOM_TYPE_OBJECT;
        }
    }

    args_pushed += 1;
    if (args_pushed < 2) {
        if (__consume_token(parser, TOK_COMMA)) {
            log_error("__consume_token() FAILED\n");
            return -1;
        }

        token = __next_token(parser);
        goto push_arg;
    }

    return 0;
}

static int
__parse_atom(struct my_parser * parser)
{
    struct my_token * token = __next_token(parser);

    struct policy_atom * atom = NULL;


    // create the policy_atom
    if (token->type == TOK_IDENTIFIER) {
        atom = policy_atom_new_from_predicate(token->val);
    } else if (token_is_boolean_op(token)) {
        atom = policy_atom_new_from_predicate(my_token_to_string(token->type));
    } else {
        log_error("expected identifier or boolen op at position=%zu\n", token->pos);
        return -1;
    }

    if (atom == NULL) {
        log_error("policy_atom_new_from_predicate() FAILED\n");
        return -1;
    }

    if (__consume_token(parser, TOK_LPAREN)) {
        log_error("__consume_token() FAILED\n");
        goto out_err;
    }

    if (atom->pred_type == PREDICATE_BOOL) {
        if (__parse_boolean_atom_type(parser, atom)) {
            log_error("__parse_boolean_atom_type() FAILED\n");
            goto out_err;
        }
    } else {
        if (__parse_regular_atom_type(parser, atom)) {
            log_error("__parse_regular_atom_type() FAILED\n");
            goto out_err;
        }
    }

    if (__consume_token(parser, TOK_RPAREN)) {
        log_error("__consume_token() FAILED\n");
        goto out_err;
    }

out_success:
    if (!policy_atom_is_valid(atom)) {
        log_error("policy_atom_is_valid() FAILED\n");
        goto out_err;
    }

    if (policy_rule_push_atom(parser->policy_rule, atom)) {
        log_error("policy_rule_push_atom() FAILED\n");
        goto out_err;
    }

    return 0;

out_err:
    policy_atom_free(atom);
    return -1;
}

static int
__parse_rule(struct my_parser * parser)
{
    struct my_token * token = __next_token(parser);

    if (token->type != TOK_IDENTIFIER) {
        log_error("expected identifier at position=%zu\n", token->pos);
        return -1;
    }

    parser->policy_rule = policy_rule_new_from_perm_str(token->val);
    if (parser->policy_rule == NULL) {
        log_error("could not create policy rule from (%s)\n", token->val);
        return -1;
    }

    if (__consume_token(parser, TOK_COLONEQUALS)) {
        log_error("__consume_token() FAILED\n");
        return -1;
    }

repeat:
    if (__parse_atom(parser)) {
        log_error("__parse_atom() FAILED\n");
        return -1;
    }

    token = __next_token(parser);
    if (token->type == TOK_COMMA) {
        goto repeat;
    }

    return 0;
}

/// builds program from lexed output
struct policy_rule *
parse_abac_policy(char * policy_string)
{
    struct policy_rule * rule = NULL;

    struct my_lexer  * lexer  = lexer_create(policy_string);
    struct my_parser * parser = parser_new(lexer);

    if (__parse_rule(parser)) {
        log_error("__parse_rule() FAILED\n");
        return NULL;
    }

    // the rule returns with the token consumed
    if (parser->token->type != TOK_END) {
        log_error("unexpected token at position=%zu\n", parser->token->pos);
        if (parser->policy_rule) {
            policy_rule_free(parser->policy_rule);
        }

        parser_free(parser);
        return NULL;
    }

    rule = parser->policy_rule;
    parser_free(parser);
    lexer_destroy(lexer);

    return rule;
}
