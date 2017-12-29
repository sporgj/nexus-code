/*
 * Copyright (c) 2013 Yaroslav Stavnichiy <yarosla@gmail.com>
 * 
 * Modifications (c) 2017 Jack Lange <jacklange@cs.pitt.edu>
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
#include <stdarg.h>

#include "nxjson.h"

// redefine NX_JSON_CALLOC & NX_JSON_FREE to use custom allocator
#ifndef NX_JSON_CALLOC
#define NX_JSON_CALLOC() calloc(1, sizeof(struct nx_json))
#define NX_JSON_FREE(json) free((void *)(json))
#endif

// redefine NX_JSON_REPORT_ERROR to use custom error reporting
#ifndef NX_JSON_REPORT_ERROR
#define NX_JSON_REPORT_ERROR(msg, p) log_error("NXJSON error (%s) (p=%s)\n", msg, p)
#endif

#define IS_WHITESPACE(c) ((unsigned char)(c) <= (unsigned char)' ')


static void
__add_child(struct nx_json * parent,
	    struct nx_json * child)
{
    if (!parent->last_child) {
	parent->child            = child;
	parent->last_child       = child;
    } else {
	parent->last_child->next = child;
	parent->last_child       = child;
    }
    
    parent->length++;

    return;
}

static void
__del_child(struct nx_json * parent,
	    struct nx_json * child)
{
    struct nx_json * iter     = parent->child;
    struct nx_json * tmp_iter = NULL;
    
    while (iter != NULL) {
	
	if (iter == child) {
	    break;
	}
	
	tmp_iter = iter;
	iter     = iter->next;
    }
    
    assert(iter != NULL);
    
    if (tmp_iter == NULL) {
	parent->child  = iter->next;
    } else {
	tmp_iter->next = iter->next;
    }
    
    if (parent->last_child == iter) {
	parent->last_child = tmp_iter;
    }
    
    parent->length--;    
    
    return;
}

static struct nx_json *
create_json(nx_json_type     type,
	    char           * key,
	    struct nx_json * parent)
{
    struct nx_json * js = NX_JSON_CALLOC();
    
    assert(js);

    js->type   = type;
    js->key    = key;
    js->parent = parent;

    if (parent != NULL) {
	__add_child(parent, js);
    } else {
	js->root = 1;
    }

    
    return js;
}

static void
nx_json_free(struct nx_json * js)
{
    /* Unlink from parent */
    if (js->parent) {
	__del_child(js->parent, js);
    }

    
    /* Free everything contained in this object */
    while (js->child) {	    
	nx_json_free(js->child);
    }

    
    /* Free object itself */
    if (js->raw_string != NULL) {
	NX_JSON_FREE(js->raw_string);
    }

    
    NX_JSON_FREE(js);
}

struct nx_json_serializer {
    char     * str;
    uint32_t   len;
    uint32_t   off;
    uint32_t   lvl;
};


static int
__resize_srlzer(struct nx_json_serializer * srlzer)
{
    void * tmp_ptr = NULL;
    
    tmp_ptr = realloc(srlzer->str, srlzer->len * 2);

    if (tmp_ptr == NULL) {
	log_error("Could not resize serializer string (Req Size=%d)\n", srlzer->len * 2);
	return -1;
    }
	
    srlzer->str  = tmp_ptr;
    srlzer->len *= 2;
    
    memset(srlzer->str + srlzer->off, 0, srlzer->len - srlzer->off);
    
    return 0;
}


static int
__srlzer_append(struct nx_json_serializer * srlzer, char * fmt, ...)
{
    va_list  args;
    uint32_t ret = 0;

#if 0
    /* For debugging */
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
#endif

    /* Note: The logic order here is inverted, so ret must be zero before entering the loop */
    do {
	if (ret >= (srlzer->len - srlzer->off)) {
	    // printf("Resizing for fmt (%s)\n", fmt);
	    if (__resize_srlzer(srlzer) == -1) {
		return -1;
	    }
	    
	}
	
	// Reminder: snprintf returns the total # of bytes it was trying to write
	va_start(args, fmt);
	ret = vsnprintf(srlzer->str + srlzer->off, srlzer->len - srlzer->off, fmt, args);	
	va_end(args);

    } while (ret >= (srlzer->len - srlzer->off));

    srlzer->off += ret;
    
    

    return 0;
    
}

static int
__srlzer_indent(struct nx_json_serializer * srlzer)
{
    uint32_t i   = 0;

    /* Add tabs for indent level */	
    for (i = 0; i < srlzer->lvl; i++) {	    
	__srlzer_append(srlzer, "\t");
    }    
    
    return 0;
}


static int
__nx_json_serialize(struct nx_json            * json,
		    struct nx_json_serializer * srlzer)
{

    __srlzer_indent(srlzer);
    
    if (json->root == 0) {

	if ( (json->type         != NX_JSON_OBJECT) ||
	     (json->parent->type != NX_JSON_ARRAY) ) {

	    __srlzer_append(srlzer, "\"%s\": ", json->key);
	}
    } 

    switch (json->type) {

	case NX_JSON_OBJECT: {
	    struct nx_json * iter = json->child;

	    __srlzer_append(srlzer, "{\n");

	    srlzer->lvl++;

	    while (iter) {
		if (__nx_json_serialize(iter, srlzer) == -1) {
		    return -1;
		}
		
		iter = iter->next;

		if (iter) {
		    __srlzer_append(srlzer, ",\n");
		} else {
		    __srlzer_append(srlzer, "\n");
		}
		
	    }
	    
	    srlzer->lvl--;

	    __srlzer_indent(srlzer);
	    __srlzer_append(srlzer, "}");
	    
	    break;
	}
	case NX_JSON_ARRAY: {
	    struct nx_json * iter = json->child;

	    __srlzer_append(srlzer, "[\n");

	    srlzer->lvl++;


	    while (iter) {
		if (__nx_json_serialize(iter, srlzer) == -1) {
		    return -1;
		}

		
		iter = iter->next;

		if (iter) {
		    __srlzer_append(srlzer, ",\n");
		} else {
		    __srlzer_append(srlzer, "\n");
		}

	    }

	    srlzer->lvl--;

	    __srlzer_indent(srlzer);
	    __srlzer_append(srlzer, "]");
	    
	    break;
	}
	case NX_JSON_STRING:
	    __srlzer_append(srlzer, "\"%s\"", json->text_value);
	    break;
	case NX_JSON_INTEGER:
	    __srlzer_append(srlzer, "%lld", json->int_value);
	    break;
	case NX_JSON_DOUBLE:
	    __srlzer_append(srlzer, "%f", json->dbl_value);
	    break;
	case NX_JSON_BOOL:
	    __srlzer_append(srlzer, "%s", (json->int_value == 1) ? "true" : "false");
	    break;
	default:
	    log_error("Error: Weird json Object type in serialization (%d)\n", json->type);
	    return -1;
    }
	    
	    
    return 0;
}



static char *
nx_json_serialize(struct nx_json * json)
{
    struct nx_json_serializer srlzer;
    int ret = 0;
    
    srlzer.str = calloc(sizeof(char), 512);
    srlzer.len = 512;
    srlzer.off = 0;
    srlzer.lvl = 0;


    ret = __nx_json_serialize(json, &srlzer);

    if (ret != 0) {
	log_error("Error serializing JSON\n");
	NX_JSON_FREE(srlzer.str);
	return NULL;
    }

    
    return srlzer.str;
}




static int
nx_json_splice(struct nx_json * parent,
	       struct nx_json * new_json)
{
    if (new_json->parent) {
	__del_child(new_json->parent, new_json);
    }
    
    new_json->parent = parent;
    new_json->root   = 0;       // Clear the root flag

    __add_child(parent, new_json);

    return 0;
}

static int
nx_json_split(struct nx_json * obj)
{
    if (obj->parent) {
	__del_child(obj->parent, obj);
    }

    obj->parent = NULL;
    obj->root   = 1;

    return 0;
}


static struct nx_json *
nx_json_add(struct nx_json * json,
	    char           * key,
	    struct nx_json * val)
{
    struct nx_json * new_json = NULL;

    assert(json->type == NX_JSON_OBJECT);
    
    new_json = create_json(val->type, key, json);


    switch (val->type) {
	case NX_JSON_STRING:
	    new_json->raw_string = strdup(val->text_value);
	    new_json->text_value = new_json->raw_string;
	    break;
	    
	case NX_JSON_INTEGER:
	case NX_JSON_BOOL:
	    new_json->int_value = val->int_value;
	    break;
	    
	case NX_JSON_DOUBLE:
	    new_json->dbl_value = val->dbl_value;
	    break;
	    
	case NX_JSON_ARRAY:
	case NX_JSON_OBJECT:
	case NX_JSON_NULL:
	default:
	    // Do nothing ?
	    break;
    }
    
    return new_json;
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

static int
nx_json_del(struct nx_json * json,
	    char           * key)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(json, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    nx_json_free(tgt_obj);

    return 0;
}


static int
nx_json_set(struct nx_json * json,
	    char           * key,
	    struct nx_json * val)
{
    struct nx_json * tgt_obj = NULL;

    assert(json->type == NX_JSON_OBJECT);

    tgt_obj = nx_json_get(json, key);

    if (tgt_obj->type != val->type) {
	log_error("Type mismatch\n");
	return -1;
    }
    

    switch (val->type) {
	case NX_JSON_STRING:
	    tgt_obj->raw_string = strdup(val->text_value);
	    tgt_obj->text_value = tgt_obj->raw_string;
	    break;
	    
	case NX_JSON_INTEGER:
	case NX_JSON_BOOL:
	    tgt_obj->int_value = val->int_value;
	    break;
	    
	case NX_JSON_DOUBLE:
	    tgt_obj->dbl_value = val->dbl_value;
	    break;
	    
	case NX_JSON_ARRAY:
	case NX_JSON_OBJECT:
	case NX_JSON_NULL:
	default:
	    // Do nothing ?
	    break;
    }
    
    return 0;
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

    printf("json parsing (%s)\n", text);
    
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
    js.child->root       = 1;
    js.child->parent     = NULL;
    
    return js.child;
}




static struct nx_json *
nx_json_get_item(struct nx_json * json,
		 int              idx)
{
    struct nx_json * js = NULL;
    
    assert(json != NULL);
    
    for (js = json->child; js; js = js->next) {

	if (!idx--) {
	    return js;
	}
    }

    return NULL; 
}


static int
nx_json_set_item(struct nx_json * json,
		 int              idx,
		 struct nx_json * new_val)
{
    struct nx_json * tgt_item = NULL;

    assert(json->type == NX_JSON_ARRAY);

    tgt_item = nx_json_get_item(json, idx);
    
    if (tgt_item->type != new_val->type) {
	log_error("Type mismatch\n");
	return -1;
    }

    switch (new_val->type) {
	case NX_JSON_STRING:
	    tgt_item->raw_string = strdup(new_val->text_value);
	    tgt_item->text_value = tgt_item->raw_string;
	    break;
	    
	case NX_JSON_INTEGER:
	case NX_JSON_BOOL:
	    tgt_item->int_value = new_val->int_value;
	    break;
	    
	case NX_JSON_DOUBLE:
	    tgt_item->dbl_value = new_val->dbl_value;
	    break;
	    
	case NX_JSON_ARRAY:
	case NX_JSON_OBJECT:
	case NX_JSON_NULL:
	default:
	    // Do nothing ?
	    break;
    }	

    return 0;
}

/* Returns the index at which the item was added */
static int
nx_json_add_item(struct nx_json * json,
		 struct nx_json * item)
{
    struct nx_json * new_item = NULL;

    assert(json->type == NX_JSON_ARRAY);

    new_item = create_json(item->type, NULL, json);

    switch (item->type) {
	case NX_JSON_STRING:
	    new_item->raw_string = strdup(item->text_value);
	    new_item->text_value = new_item->raw_string;
	    break;
	    
	case NX_JSON_INTEGER:
	case NX_JSON_BOOL:
	    new_item->int_value = item->int_value;
	    break;
	    
	case NX_JSON_DOUBLE:
	    new_item->dbl_value = item->dbl_value;
	    break;
	    
	case NX_JSON_ARRAY:
	case NX_JSON_OBJECT:
	case NX_JSON_NULL:
	default:
	    // Do nothing ?
	    break;
    }

    return new_item->parent->length - 1;
}


static int
nx_json_del_item(struct nx_json * json,
		 int              idx)
{
    struct nx_json * tgt_item = NULL;

    assert(json->type == NX_JSON_ARRAY);

    tgt_item = nx_json_get_item(json, idx);

    nx_json_free(tgt_item);
    
    return 0;
}




#ifdef  __cplusplus
}
#endif

#endif  /* NXJSON_C */
