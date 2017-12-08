#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


#include <nexus_json.h>

#include <nexus_raw_file.h>
#include <nexus_util.h>
#include <nexus_log.h>


/* Internalize nxjson functions */
#include <nxjson.h>
#include <nxjson.c>




nexus_json_obj_t
nexus_json_parse_str(char * str)
{
    nexus_json_obj_t new_obj = NEXUS_JSON_INVALID_OBJ;

    new_obj = nx_json_parse(str);

    if (new_obj == NULL) {
	log_error("Could not parse JSON string (%s)\n", str);
	return NEXUS_JSON_INVALID_OBJ;
    }

    return new_obj;
}

nexus_json_obj_t
nexus_json_parse_file(char * file_name)
{
    nexus_json_obj_t obj      = NEXUS_JSON_INVALID_OBJ;

    char           * json_str = NULL;
    size_t           json_len = 0;

    int ret = 0;

    
    ret = nexus_read_raw_file(file_name, (uint8_t **)&json_str, &json_len);

    if (ret == -1) {
	log_error("Could not read JSON file (%s)\n", file_name);
	return NEXUS_JSON_INVALID_OBJ;
    }

    obj = nexus_json_parse_str(json_str);

    nexus_free(json_str);

    return obj;
}


void
nexus_json_free_object(nexus_json_obj_t object)
{
    assert(object != NULL);

    nx_json_free(object);

    return;
}


nexus_json_obj_t
nexus_json_get_object(nexus_json_obj_t   obj,
		      char             * key)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return NEXUS_JSON_INVALID_OBJ;
    }

    if (tgt_obj->type != NX_JSON_OBJECT) {
	return NEXUS_JSON_INVALID_OBJ;
    }
    
    
    return tgt_obj;
}


char *
nexus_json_get_string(nexus_json_obj_t   obj,
		      char             * key)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return NEXUS_JSON_INVALID_OBJ;
    }

    if (tgt_obj->type != NX_JSON_STRING) {
	return NEXUS_JSON_INVALID_OBJ;
    }

    return tgt_obj->text_value;
}



/* Fills in parameter structure with results from a parsed JSON string
 * Return Value:
 *  0 = Success
 *  1 = More tokens than params
 * -1 = Parse Error
 */

int
nexus_json_get_params(nexus_json_obj_t          obj,
		      struct nexus_json_param * params,
		      uint32_t                  num_params)
{
    uint32_t i   = 0;
    int      ret = 0;
    
    /* Check Params and grab values */
    for (i = 0; i < num_params; i++) {
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, params[i].name);

	if (tgt_obj == NULL) {
	    log_error("Invalid JSON for given parameters\n");
	    return -1;
	}

	
	switch (params[i].type) {
	    case NEXUS_JSON_U8:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}
		
		if (tgt_obj->int_value > UCHAR_MAX) {
		    ret = -1;		    
		    log_error("NEXUS_JSON_U8 Conversion error\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;
		
		break;
	    case NEXUS_JSON_S8:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}


		if ((tgt_obj->int_value > SCHAR_MAX) ||
		    (tgt_obj->int_value < SCHAR_MIN)) {
		    ret = -1;		    
		    log_error("NEXUS_JSON_S8 Conversion error\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;



		break;
	    case NEXUS_JSON_U16:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		if (tgt_obj->int_value > USHRT_MAX) {
		    ret = -1;		    
		    log_error("NEXUS_JSON_U16 Conversion error\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;

		

		break;
	    case NEXUS_JSON_S16:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		if ((tgt_obj->int_value > SHRT_MAX) ||
		    (tgt_obj->int_value < SHRT_MIN)) {
		    ret = -1;		    
		    log_error("NEXUS_JSON_S16 Conversion error\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;

		break;
	    case NEXUS_JSON_U32:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		if (tgt_obj->int_value > UINT_MAX) {
		    ret = -1;		    
		    log_error("NEXUS_JSON_U32 Conversion error\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;
	
		break;
	    case NEXUS_JSON_S32:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;

		}

		if ((tgt_obj->int_value > INT_MAX) ||
		    (tgt_obj->int_value < INT_MIN)) {
		    ret = -1;		    
		    log_error("NEXUS_JSON_S32 Conversion error\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;

		break;
	    case NEXUS_JSON_U64:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;

		break;
	    case NEXUS_JSON_S64:
		if (tgt_obj->type != NX_JSON_INTEGER) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		params[i].val = tgt_obj->int_value;

		break;
	   
	    case NEXUS_JSON_STRING: {
		
		if (tgt_obj->type != NX_JSON_STRING) {
		    log_error("JSON Error: type mismatch\n");
		    goto out;
		}

		params[i].ptr = tgt_obj->text_value;
		
		break;
	    }
	    case NEXUS_JSON_OBJECT:
		log_error("NEXUS_JSON_OBJECT not currently supported\n");
		goto out;
	    default:
		log_error("Error Invalid Parameter Type (%d)\n", params[i].type);
		goto out;
	}
	
	
    }


 out:   
    if (ret < 0) {
	log_error("Error Parsing JSON value\n");
    }
    
  
    return ret;
    
}
