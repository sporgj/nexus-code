/*
 * Copyright (c) 2013 Yaroslav Stavnichiy <yarosla@gmail.com>
 *
 * This file is part of NXJSON.
 *
 * NXJSON is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * NXJSON is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with NXJSON. If not, see <http://www.gnu.org/licenses/>.
 */

// this file can be #included in your code
#ifndef NXJSON_C
#define NXJSON_C

#ifdef  __cplusplus
extern "C" {
#endif


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "nxjson.h"

// redefine NX_JSON_CALLOC & NX_JSON_FREE to use custom allocator
#ifndef NX_JSON_CALLOC
#define NX_JSON_CALLOC() calloc(1, sizeof(struct nx_json))
#define NX_JSON_FREE(json) free((void*)(json))
#endif

// redefine NX_JSON_REPORT_ERROR to use custom error reporting
#ifndef NX_JSON_REPORT_ERROR
#define NX_JSON_REPORT_ERROR(msg, p) log_error("NXJSON error (%s) (p=%s)\n", msg, p)
#endif

#define IS_WHITESPACE(c) ((unsigned char)(c) <= (unsigned char)' ')


static struct nx_json *
create_json(nx_json_type     type,
	    char           * key,
	    struct nx_json * parent)
{
    struct nx_json* js = NX_JSON_CALLOC();
    
    assert(js);

    js->type = type;
    js->key  = key;
    
    if (!parent->last_child) {
	parent->child            = js;
	parent->last_child       = js;
    } else {
	parent->last_child->next = js;
	parent->last_child       = js;
    }
    
    parent->length++;
    
    return js;
}

static void
nx_json_free(struct nx_json * js)
{
    struct nx_json * p  = js->child;
    struct nx_json * p1 = NULL;

    assert(js->raw_string != NULL);
    
    while (p) {
	p1 = p->next;

	nx_json_free(p);

	p  = p1;
    }
    
    NX_JSON_FREE(js->raw_string);
    NX_JSON_FREE(js);
}


static inline int hex_val(char c) {
    if ((c >= '0') && (c <= '9')) return (c - '0');
    if ((c >= 'a') && (c <= 'f')) return (c - 'a' + 10);
    if ((c >= 'A') && (c <= 'F')) return (c - 'A' + 10);
    return -1;
}

static char *
unescape_string(char  * s,
		char ** end)
{
    char * p = s;
    char * d = s;
    char   c;

    while ((c = *p++)) {

	if (c == '"') {
	    *d   = '\0';
	    *end = p;

	    return s;
	} else if (c == '\\') {

	    switch (*p) {
		case '\\':
		case '/':
		case '"':
		    *d++ = *p++;
		    break;
		case 'b':
		    *d++ = '\b';
		    p++;
		    break;
		case 'f':
		    *d++ = '\f';
		    p++;
		    break;
		case 'n':
		    *d++ = '\n';
		    p++;
		    break;
		case 'r':
		    *d++ = '\r';
		    p++;
		    break;
		case 't':
		    *d++ = '\t';
		    p++;
		    break;

		default:
		    // leave untouched
		    *d++ = c;
		    break;
	    }
	} else {
	    *d++ = c;
	}
    }

    NX_JSON_REPORT_ERROR("no closing quote for string", s);

    return 0;
}

static char *
skip_block_comment(char * p) {
    // assume p[-2]=='/' && p[-1]=='*'
    char * ps = (p - 2);

    if (!*p) {
	NX_JSON_REPORT_ERROR("endless comment", ps);
	return 0;
    }
    
 REPEAT:
    p = strchr(p + 1, '/');

    if (!p) {
	NX_JSON_REPORT_ERROR("endless comment", ps);
	return 0;
    }

    if (p[-1] != '*') {
	goto REPEAT;
    }
    
    return p + 1;
}

static char *
parse_key(char ** key,
	  char  * p) {
    // on '}' return with *p=='}'

    char c;

    while ((c = *p++)) {

	if (c == '"') {
	    *key = unescape_string(p, &p);

	    if (!*key) {
		return 0; // propagate error
	    }
	    
	    while ((*p) &&
		   (IS_WHITESPACE(*p))) {
		p++;
	    }
	    
	    if (*p == ':') {
		return p + 1;
	    }
	    
	    NX_JSON_REPORT_ERROR("unexpected chars", p);

	    return 0;
	    
	} else if (IS_WHITESPACE(c) ||
		   (c == ',')) {

	    // continue

	} else if (c == '}') {

	    return p - 1;

	} else if (c == '/') {

	    if (*p == '/') { // line comment

		char * ps = (p - 1);

		p = strchr(p + 1, '\n');

		if (!p) {
		    NX_JSON_REPORT_ERROR("endless comment", ps);
		    return 0; // error
		}

		p++;

	    } else if (*p == '*') { // block comment
		p = skip_block_comment(p + 1);

		if (!p) {
		    return 0;
		}
		
	    } else {
		NX_JSON_REPORT_ERROR("unexpected chars", p - 1);
		return 0; // error
	    }
	} else {
	    NX_JSON_REPORT_ERROR("unexpected chars", p - 1);
	    return 0; // error
	}
    }
    
    NX_JSON_REPORT_ERROR("unexpected chars", p - 1);

    return 0; // error
}

static char *
parse_value(struct nx_json * parent,
	    char           * key,
	    char           * p)
{

    struct nx_json * js = NULL;

    while (1) {

	switch (*p) {

	    case '\0':
		NX_JSON_REPORT_ERROR("unexpected end of text", p);
		return 0; // error

	    case ' ' :
	    case '\t':
	    case '\n':
	    case '\r':
	    case ',' :
		// skip
		p++;
		break;

	    case '{':
		
		js = create_json(NX_JSON_OBJECT, key, parent);
		p++;
		
		while (1) {
		    char * new_key = NULL;

		    p = parse_key(&new_key, p);

		    if (!p) {
			return 0; // error
		    }
		    
		    if (*p == '}') {
			return p + 1; // end of object
		    }
		    
		    p = parse_value(js, new_key, p);

		    if (!p) {
			return 0; // error
		    }
		}
	    case '[':

		js = create_json(NX_JSON_ARRAY, key, parent);
		p++;
		
		while (1) {
		    p = parse_value(js, 0, p);

		    if (!p) {
			return 0; // error
		    }
		    
		    if (*p == ']') {
			return p + 1; // end of array
		    }
		}

	    case ']':
		return p;

	    case '"':
		p++;
		
		js             = create_json(NX_JSON_STRING, key, parent);
		js->text_value = unescape_string(p, &p);

		if (!js->text_value) {
		    return 0; // propagate error
		}
		
		return p;

	    case '-':
	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9': {
		char * pe = NULL;

		js            = create_json(NX_JSON_INTEGER, key, parent);
		js->int_value = strtoll(p, &pe, 0);
		
		if ( (pe    == p) ||
		     (errno == ERANGE) ) {

		    NX_JSON_REPORT_ERROR("invalid number", p);
		    return 0; // error
		}
		
		if ( (*pe == '.') ||
		     (*pe == 'e') ||
		     (*pe == 'E') ) { // double value
		    
		    js->type      = NX_JSON_DOUBLE;
		    js->dbl_value = strtod(p, &pe);

		    if ( (pe    == p) ||
			 (errno == ERANGE) ) {

			NX_JSON_REPORT_ERROR("invalid number", p);
			return 0; // error
		    }
		}
		else {
		    js->dbl_value = js->int_value;
		}
		
		return pe;
	    }
	    case 't':
		if (strncmp(p, "true", 4) == 0) {
		    js            = create_json(NX_JSON_BOOL, key, parent);
		    js->int_value = 1;
		    return p + 4;
		}
		
		NX_JSON_REPORT_ERROR("unexpected chars", p);
		return 0; // error

	    case 'f':

		if (strncmp(p, "false", 5) == 0) {
		    js            = create_json(NX_JSON_BOOL, key, parent);
		    js->int_value = 0;
		    
		    return p + 5;
		}

		NX_JSON_REPORT_ERROR("unexpected chars", p);
		return 0; // error

	    case 'n':

		if (strncmp(p, "null", 4) == 0) {
		    create_json(NX_JSON_NULL, key, parent);
		    return p + 4;
		}

		NX_JSON_REPORT_ERROR("unexpected chars", p);
		return 0; // error

	    case '/': // comment
		
		if (p[1] == '/') { // line comment
		    char * ps = p;

		    p = strchr(p + 2, '\n');

		    if (!p) {
			NX_JSON_REPORT_ERROR("endless comment", ps);
			return 0; // error
		    }
		    p++;
		} else if (p[1] == '*') { // block comment

		    p = skip_block_comment(p + 2);

		    if (!p) {
			return 0;
		    }
		} else {
		    NX_JSON_REPORT_ERROR("unexpected chars", p);
		    return 0; // error
		}
		break;
	    default:
		NX_JSON_REPORT_ERROR("unexpected chars", p);
		return 0; // error
	}
    }
}

static struct nx_json *
nx_json_parse(char * text)
{
    struct nx_json js = {0};
    char * raw_text   = NULL;

    raw_text = strdup(text);

    if (raw_text == NULL) {
	return NULL;
    }
    
    if (parse_value(&js, 0, raw_text) == 0) {

	if (js.child) {
	    nx_json_free(js.child);
	}
	
	NX_JSON_FREE(raw_text);
	return NULL;
    }

    js.child->raw_string = raw_text;
    
    
    return js.child;
}

static struct nx_json *
nx_json_get(struct nx_json * json,
	    char           * key)
{
    struct nx_json * js = NULL;

    assert(json != NULL);
    assert(key  != NULL);
    
    
    for (js = json->child; js; js = js->next) {

	if ( (js->key) &&
	     (strcmp(js->key, key) == 0)) {
		
	    return js;
	}
    }
    
    return NULL;
}

#if 0
static struct nx_json *
nx_json_item(struct nx_json * json,
	     int              idx)
{
    struct nx_json * js = NULL;
    
    assert(json != NULL);
    
    for (js = json->child; js; js = js->next) {

	if (!idx--) {
	    return js;
	}
    }

    return NULL; // never return null
}
#endif

#ifdef  __cplusplus
}
#endif

#endif  /* NXJSON_C */
