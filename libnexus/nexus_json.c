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
nexus_json_new()
{
    return create_json(NX_JSON_OBJECT, NULL, NULL);
}

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

int
nexus_json_add_object(nexus_json_obj_t   obj,
		      char             * key)
{
    struct nx_json new_json;

    new_json.type = NX_JSON_OBJECT;

    return nx_json_add(obj, key, &new_json);
}


int
nexus_json_del_object(nexus_json_obj_t obj)
{
    nx_json_free(obj);
    return 0;
}


int
nexus_json_del(nexus_json_obj_t   obj,
	       char             * key)
{
    nexus_json_obj_t tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    nx_json_free(tgt_obj);

    return 0;
}




int
nexus_json_get_string(nexus_json_obj_t   obj,
		      char             * key,
		      char            ** val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_STRING) {
	return -1;
    }

    *val = tgt_obj->text_value;
    
    return 0;
}


int
nexus_json_get_bool(nexus_json_obj_t   obj,
		    char             * key,
		    int              * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_BOOL) {
	return -1;
    }

    if ((tgt_obj->int_value != 0) ||
	(tgt_obj->int_value != 1)) {
	return -1;
    }
    
    *val = tgt_obj->int_value;
    
    return 0;
}


int
nexus_json_get_int(nexus_json_obj_t   obj,
		   char             * key,
		   int              * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    if ((tgt_obj->int_value > INT_MAX) ||
	(tgt_obj->int_value < INT_MIN)) {
	log_error("NEXUS_JSON_INT: Bounds Error\n");
	return -1;
    }
    
    *val = tgt_obj->int_value;

    return 0;
}

int
nexus_json_get_double(nexus_json_obj_t   obj,
		      char             * key,
		      double           * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_DOUBLE) {
	return -1;
    }

    *val = tgt_obj->dbl_value;
    
    return 0;
}


int
nexus_json_get_s8(nexus_json_obj_t   obj,
		  char             * key,
		  int8_t           * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }


    if ((tgt_obj->int_value > SCHAR_MAX) ||
	(tgt_obj->int_value < SCHAR_MIN)) {
	log_error("NEXUS_JSON_S8: Bounds Error\n");
	return -1;
    }

    *val = tgt_obj->int_value;
    
    return 0;
}

int
nexus_json_get_s16(nexus_json_obj_t   obj,
		   char             * key,
		   int16_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    if ((tgt_obj->int_value > SHRT_MAX) ||
	(tgt_obj->int_value < SHRT_MIN)) {
	log_error("NEXUS_JSON_S16: Bounds Error\n");
	return -1;
    }
    
    *val = tgt_obj->int_value;
    
    return 0;
}

int
nexus_json_get_s32(nexus_json_obj_t   obj,
		   char             * key,
		   int32_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    if ((tgt_obj->int_value > INT_MAX) ||
	(tgt_obj->int_value < INT_MIN)) {
	log_error("NEXUS_JSON_S32: Bounds Error\n");
	return -1;
    }
    
    *val = tgt_obj->int_value;
    
    return 0;
}


int
nexus_json_get_s64(nexus_json_obj_t   obj,
		   char             * key,
		   int64_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }
    
    *val = tgt_obj->int_value;
    
    return 0;
}


int
nexus_json_get_u8(nexus_json_obj_t   obj,
		  char             * key,
		  uint8_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    if (tgt_obj->int_value > UCHAR_MAX) {
	log_error("NEXUS_JSON_U8: Bounds Error\n");
	return -1;
    }
	
    *val = tgt_obj->int_value;
    
    return 0;
}

int
nexus_json_get_u16(nexus_json_obj_t   obj,
		   char             * key,
		   uint16_t         * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    if (tgt_obj->int_value > USHRT_MAX) {
	log_error("NEXUS_JSON_U16: Bounds Error\n");
	return -1;
    }

    *val = tgt_obj->int_value;
    
    return 0;
}

int
nexus_json_get_u32(nexus_json_obj_t   obj,
		   char             * key,
		   uint32_t         * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    if (tgt_obj->int_value > UINT_MAX) {
	log_error("NEXUS_JSON_U32: Bounds Error\n");
	return -1;
    }
    
    *val = tgt_obj->int_value;
    
    return 0;
}

int
nexus_json_get_u64(nexus_json_obj_t   obj,
		   char             * key,
		   uint64_t         * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get(obj, key);

    if (tgt_obj == NULL) {
	return -1;
    }

    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    *val = tgt_obj->int_value;
    
    return 0;
}







int
nexus_json_add_string(nexus_json_obj_t   obj,
		      char             * key,
		      char             * str)
{
    struct nx_json new_json;

    new_json.type       = NX_JSON_STRING;
    new_json.text_value = str;

    return nx_json_add(obj, key, &new_json);
}


int
nexus_json_add_bool(nexus_json_obj_t   obj,
		    char             * key,
		    int                val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_BOOL;
    new_json.int_value = val;

    return nx_json_add(obj, key, &new_json);    
}

int
nexus_json_add_int(nexus_json_obj_t   obj,
		   char             * key,
		   int                val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_INTEGER;
    new_json.int_value = val;

    return nx_json_add(obj, key, &new_json);    
}

int
nexus_json_add_double(nexus_json_obj_t   obj,
		      char             * key,
		      double             val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_DOUBLE;
    new_json.dbl_value = val;

    return nx_json_add(obj, key, &new_json);    
}

int
nexus_json_add_s64(nexus_json_obj_t   obj,
		   char             * key,
		   int64_t            val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_INTEGER;
    new_json.int_value = val;

    return nx_json_add(obj, key, &new_json);    
}

int
nexus_json_add_u64(nexus_json_obj_t   obj,
		   char             * key,
		   uint64_t           val)
{
    return nexus_json_add_s64(obj, key, val);
}

int
nexus_json_add_s8(nexus_json_obj_t   obj,
		  char             * key,
		  int8_t             val)
{
    return nexus_json_add_s64(obj, key, val);
}

int
nexus_json_add_s16(nexus_json_obj_t   obj,
		   char             * key,
		   int16_t            val)
{
    return nexus_json_add_s64(obj, key, val);
}

int
nexus_json_add_s32(nexus_json_obj_t   obj,
		   char             * key,
		   int32_t            val)
{
    return nexus_json_add_s64(obj, key, val);
}

							                  
int
nexus_json_add_u8(nexus_json_obj_t   obj,
		  char             * key,
		  uint8_t            val)
{
    return nexus_json_add_s64(obj, key, val);
}

int
nexus_json_add_u16(nexus_json_obj_t   obj,
		   char             * key,
		   uint16_t           val)
{
    return nexus_json_add_s64(obj, key, val);
}

int
nexus_json_add_u32(nexus_json_obj_t   obj,
		   char             * key,
		   uint32_t           val)
{
    return nexus_json_add_s64(obj, key, val);
}




int
nexus_json_set_string(nexus_json_obj_t   obj,
		      char             * key,
		      char             * str)
{
    struct nx_json new_val;

    new_val.type       = NX_JSON_STRING;
    new_val.text_value = str;

    return nx_json_set(obj, key, &new_val);
}


int
nexus_json_set_bool(nexus_json_obj_t   obj,
		    char             * key,
		    int                val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_BOOL;
    new_val.int_value = val;

    return nx_json_set(obj, key, &new_val);    
}

int
nexus_json_set_int(nexus_json_obj_t   obj,
		   char             * key,
		   int                val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_INTEGER;
    new_val.int_value = val;

    return nx_json_set(obj, key, &new_val);    
}

int
nexus_json_set_double(nexus_json_obj_t   obj,
		      char             * key,
		      double             val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_DOUBLE;
    new_val.dbl_value = val;

    return nx_json_set(obj, key, &new_val);    
}

int
nexus_json_set_s64(nexus_json_obj_t   obj,
		   char             * key,
		   int64_t            val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_INTEGER;
    new_val.int_value = val;

    return nx_json_set(obj, key, &new_val);    
}

int
nexus_json_set_u64(nexus_json_obj_t   obj,
		   char             * key,
		   uint64_t           val)
{
    return nexus_json_set_s64(obj, key, val);
}

int
nexus_json_set_s8(nexus_json_obj_t   obj,
		  char             * key,
		  int8_t             val)
{
    return nexus_json_set_s64(obj, key, val);
}

int
nexus_json_set_s16(nexus_json_obj_t   obj,
		   char             * key,
		   int16_t            val)
{
    return nexus_json_set_s64(obj, key, val);
}

int
nexus_json_set_s32(nexus_json_obj_t   obj,
		   char             * key,
		   int32_t            val)
{
    return nexus_json_set_s64(obj, key, val);
}

							                  
int
nexus_json_set_u8(nexus_json_obj_t   obj,
		  char             * key,
		  uint8_t            val)
{
    return nexus_json_set_s64(obj, key, val);
}

int
nexus_json_set_u16(nexus_json_obj_t   obj,
		   char             * key,
		   uint16_t           val)
{
    return nexus_json_set_s64(obj, key, val);
}

int
nexus_json_set_u32(nexus_json_obj_t   obj,
		   char             * key,
		   uint32_t           val)
{
    return nexus_json_set_s64(obj, key, val);
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

	switch (params[i].type) {
	    case NEXUS_JSON_U8:
		ret = nexus_json_get_u8 (obj, params[i].name, (uint8_t  *)&params[i].val);
		break;
	    case NEXUS_JSON_S8:
		ret = nexus_json_get_s8 (obj, params[i].name, (int8_t   *)&params[i].val);
		break;
	    case NEXUS_JSON_U16:
		ret = nexus_json_get_u16(obj, params[i].name, (uint16_t *)&params[i].val);
		break;
	    case NEXUS_JSON_S16:
		ret = nexus_json_get_s16(obj, params[i].name, (int16_t  *)&params[i].val);
		break;
	    case NEXUS_JSON_U32:
		ret = nexus_json_get_u32(obj, params[i].name, (uint32_t *)&params[i].val);
		break;
	    case NEXUS_JSON_S32:
		ret = nexus_json_get_s32(obj, params[i].name, (int32_t  *)&params[i].val);
		break;
	    case NEXUS_JSON_U64:
		ret = nexus_json_get_u64(obj, params[i].name, (uint64_t *)&params[i].val);
		break;
	    case NEXUS_JSON_S64:
		ret = nexus_json_get_s64(obj, params[i].name, (int64_t  *)&params[i].val);
		break;
	    case NEXUS_JSON_STRING: {	       
		ret = nexus_json_get_string(obj, params[i].name, (char **)&params[i].ptr);
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




char *
nexus_json_serialize(nexus_json_obj_t obj)
{
    return nx_json_serialize(obj);
}
