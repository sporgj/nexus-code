#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "jsmn.h"
#include "nexus_json.h"

#include "nexus_internal.h"

static int
safe_strtou8(char    * str,
	     uint8_t * value)
{
    unsigned long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoul(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if (tmp > UCHAR_MAX) {
	/* value exceeded requested size */
	return -1;
    }
	   
    *value = (uint8_t)tmp;    
    return 0;
}

static int
safe_strtoi8(char    * str,
	     int8_t * value)
{
    long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtol(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if ((tmp > SCHAR_MAX) ||
	(tmp < SCHAR_MIN)) {
	/* value exceeded requested size */
	return -1;
    }
	   	
    *value = (int8_t)tmp;    
    return 0;
}



static int
safe_strtou16(char     * str,
	      uint16_t * value)
{
    unsigned long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoul(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if (tmp > USHRT_MAX) {
	/* value exceeded requested size */
	return -1;
    }
	   
    *value = (uint16_t)tmp;    
    return 0;
}

static int
safe_strtoi16(char     * str,
	      int16_t * value)
{
    long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtol(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if ((tmp > SHRT_MAX) ||
	(tmp < SHRT_MIN)) {
	/* value exceeded requested size */
	return -1;
    }
	   	
    *value = (int16_t)tmp;    
    return 0;
}

static int
safe_strtou32(char     * str,
	      uint32_t * value)
{
    unsigned long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoul(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   
    *value = (uint32_t)tmp;    
    return 0;
}

static int
safe_strtoi32(char     * str,
	      int32_t * value)
{
    long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtol(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   	
    *value = (int32_t)tmp;    
    return 0;
}


static int
safe_strtou64(char     * str,
	      uint64_t * value)
{
    unsigned long long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoull(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   
    *value = (uint64_t)tmp;    
    return 0;
}

static int
safe_strtoi64(char     * str,
	      int64_t * value)
{
    long long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoll(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   	
    *value = (int64_t)tmp;    
    return 0;
}



/* Fills in parameter structure with results from a parsed JSON string
 * Return Value:
 *  0 = Success
 *  1 = More tokens than params
 * -1 = Parse Error
 */

int
nexus_json_parse(char                    * str,
		 struct nexus_json_param * params,
		 uint32_t                  num_params)
{
    jsmn_parser   parser;
    jsmntok_t   * tokens     = NULL;

    uint32_t num_tokens = (2 * num_params);
    
    uint32_t i        = 0;
    int      ret      = -1;

    int param_overflow = 0;
    

    log_debug("Parsing JSON String:\n%s\n", str);
    
    /* Initialize JSMN parser */
    jsmn_init(&parser);

    /* Allocate tokens */
    tokens = calloc(sizeof(jsmntok_t), num_tokens);

    if (tokens == NULL) {
	log_error("Could not allocate JSMN tokens\n");
	goto out;
    }

    memset(tokens, 0, sizeof(jsmntok_t) * num_tokens);
    

    /* Parse JSON */
    ret = jsmn_parse(&parser, str, strlen(str), tokens, num_tokens);

    if (ret == JSMN_ERROR_NOMEM) {
	param_overflow = 1;
    } else if (ret < 0) {
	log_error("JSON Parse error (ret=%d)\n", ret);
	goto out;
    }

#if 0
    /* Null terminate all tokens */
    for (i = 0; i < num_tokens; i++) {
	str[tokens[i].end] = '\0';
    }
#endif
    
    /* Check Params and grab values */
    for (i = 0; i < num_params; i++) {

	jsmntok_t * name_tok = &(tokens[(i * 2)]);
	jsmntok_t *  val_tok = &(tokens[(i * 2) + 1]);
	
	char * name  = str + name_tok->start;
	char * value = str +  val_tok->start;
	
	if (strncmp(params[i].name, name, strlen(params[i].name)) != 0) {
	    log_error("Error matching JSON format (param.name = %s) (toke.name=%s)\n", params[i].name, name);
	    goto out;
	}


	switch (params[i].type) {
	    case NEXUS_JSON_U8:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}
		
		ret = safe_strtou8(value, (uint8_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_U8 Conversion error\n");
		    goto out;
		}
		
		break;
	    case NEXUS_JSON_S8:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = safe_strtoi8(value, (int8_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_S8 Conversion error\n");
		    goto out;
		}
		
		break;
	    case NEXUS_JSON_U16:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = safe_strtou16(value, (uint16_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_U16 Conversion error\n");
		    goto out;
		}
		
		break;
	    case NEXUS_JSON_S16:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = safe_strtoi16(value, (int16_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_S16 Conversion error\n");
		    goto out;
		}

		break;
	    case NEXUS_JSON_U32:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = safe_strtou32(value, (uint32_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_U32 Conversion error\n");
		    goto out;
		}
		
		break;
	    case NEXUS_JSON_S32:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;

		}
		
		ret = safe_strtoi32(value, (int32_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_S32 Conversion error\n");
		    goto out;
		}

		break;
	    case NEXUS_JSON_U64:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = safe_strtou64(value, (uint64_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_U64 Conversion error\n");
		    goto out;
		}

		break;
	    case NEXUS_JSON_S64:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = safe_strtoi64(value, (int64_t *)&(params[i].val));

		if (ret == -1) {
		    log_error("NEXUS_JSON_S64 Conversion error\n");
		    goto out;
		}

		break;
	    case NEXUS_JSON_STRING: {
		int tmp_len = val_tok->end - val_tok->start;
		
		if (val_tok->type != JSMN_STRING) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}
		
		params[i].ptr = calloc(tmp_len + 1, 1);
		strncpy(params[i].ptr, value, tmp_len);
		
		break;
	    }
	    default:
		log_error("Error Invalid Parameter Type (%d)\n", params[i].type);
		goto out;
	}
	
	
    }

    if (param_overflow) {
	ret = 1;
    } else {
	ret = 0;
    }
    
 out:
    
    if (ret < 0) {
	log_error("Error Parsing JSON value\n");
    }
    
    if (tokens) nexus_free(tokens);

    
    return ret;
    
}

/* For now just free temporary strings allocated in the params */
int
nexus_json_release_params(struct nexus_json_param * params,
			  uint32_t                  num_params)
{
    uint32_t i = 0;

    for (i = 0; i < num_params; i++) {
	if ( (params[i].type == NEXUS_JSON_STRING) &&
	     (params[i].val  != (uintptr_t)NULL) ){
	    nexus_free(params[i].ptr);
	}
    }
    
    return 0;
}
