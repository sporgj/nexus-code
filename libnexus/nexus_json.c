/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

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
nexus_json_new_obj(char * key)
{
    return create_json(NX_JSON_OBJECT, key, NULL);
}


nexus_json_obj_t
nexus_json_new_arr(char * key)
{
    return create_json(NX_JSON_ARRAY, key, NULL);
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


char *
nexus_json_serialize(nexus_json_obj_t obj)
{
    return nx_json_serialize(obj);
}


int
nexus_json_serialize_to_file(nexus_json_obj_t   obj,
			     char             * file_name)
{
    char * json_str = nx_json_serialize(obj);

    int ret = 0;
    
    if (json_str == NULL) {
	log_error("Could not serialize JSON object\n");
	return -1;
    }

    ret = nexus_write_raw_file(file_name, (uint8_t *)json_str, strlen(json_str));

    nexus_free(json_str);

    if (ret == -1) {
	log_error("Could not write JSON file (%s)\n", file_name);
	return -1;
    }

    return 0;
}

			     
void
nexus_json_free(nexus_json_obj_t object)
{
    assert(object != NULL);

    assert(((struct nx_json *)object)->root == 1);

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

nexus_json_obj_t
nexus_json_add_object(nexus_json_obj_t   obj,
		      char             * key)
{
    struct nx_json   tmp_json;
    
    tmp_json.type = NX_JSON_OBJECT;
    
    return nx_json_add(obj, key, &tmp_json);
}

int
nexus_json_splice(nexus_json_obj_t   obj,
		  nexus_json_obj_t   new_obj)
{
    return nx_json_splice(obj, new_obj);
}


int
nexus_json_split(nexus_json_obj_t obj)
{
    return nx_json_split(obj);
}


int
nexus_json_del_object(nexus_json_obj_t obj)
{
    nx_json_free(obj);
    return 0;
}


int
nexus_json_del_by_key(nexus_json_obj_t   obj,
		      char             * key)
{
    nx_json_del(obj, key);
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

nexus_json_obj_t
nexus_json_array_get_child_by_index(nexus_json_obj_t arr, int idx)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

    if (tgt_obj == NULL) {
	return NEXUS_JSON_INVALID_OBJ;
    }

    return tgt_obj;
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

    return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);
}


int
nexus_json_add_bool(nexus_json_obj_t   obj,
		    char             * key,
		    int                val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_BOOL;
    new_json.int_value = val;

    return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
nexus_json_add_int(nexus_json_obj_t   obj,
		   char             * key,
		   int                val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_INTEGER;
    new_json.int_value = val;

    return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
nexus_json_add_double(nexus_json_obj_t   obj,
		      char             * key,
		      double             val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_DOUBLE;
    new_json.dbl_value = val;

    return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
nexus_json_add_s64(nexus_json_obj_t   obj,
		   char             * key,
		   int64_t            val)
{
    struct nx_json new_json;

    new_json.type      = NX_JSON_INTEGER;
    new_json.int_value = val;

    return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
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



nexus_json_obj_t
nexus_json_get_array(nexus_json_obj_t   obj,
		     char             * key)
{
    struct nx_json * tgt_obj = NULL;
    
    tgt_obj = nx_json_get(obj, key);
    
    if (tgt_obj == NULL) {
	return NEXUS_JSON_INVALID_OBJ;
    }

    if (tgt_obj->type != NX_JSON_ARRAY) {
	return NEXUS_JSON_INVALID_OBJ;
    }    
    
    return tgt_obj;
}

int
nexus_json_get_array_len(nexus_json_obj_t arr)
{
    return ((struct nx_json *)arr)->length;
}


nexus_json_obj_t
nexus_json_add_array(nexus_json_obj_t   obj,
		     char             * key)
{
    struct nx_json new_json;
    
    new_json.type = NX_JSON_ARRAY;
    
    return nx_json_add(obj, key, &new_json);
}


int
nexus_json_del_array(nexus_json_obj_t obj)
{
    nx_json_free(obj);
    return 0;
}


nexus_json_obj_t
nexus_json_array_get_object(nexus_json_obj_t   arr,
			    int                idx)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

    if (tgt_obj == NULL) {
	return NEXUS_JSON_INVALID_OBJ;
    }
	
    if (tgt_obj->type != NX_JSON_OBJECT) {
	return NEXUS_JSON_INVALID_OBJ;
    }

    return tgt_obj;
}

int
nexus_json_array_get_string(nexus_json_obj_t    arr,
			    int                 idx,
			    char             ** val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_bool(nexus_json_obj_t   arr,
			  int                idx,
			  int              * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

    if (tgt_obj == NULL) {
	return -1;
    }
	
    if (tgt_obj->type != NX_JSON_BOOL) {
	return -1;
    }

    *val = tgt_obj->int_value;

    return 0;
}

int
nexus_json_array_get_int(nexus_json_obj_t   arr,
			 int                idx,
			 int              * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_double(nexus_json_obj_t   arr,
			    int                idx,
			    double           * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_s8(nexus_json_obj_t   arr,
			int                idx,
			int8_t           * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_s16(nexus_json_obj_t   arr,
			 int                idx,
			 int16_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_s32(nexus_json_obj_t   arr,
			 int                idx,
			 int32_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_s64(nexus_json_obj_t   arr,
			 int                idx,
			 int64_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_u8(nexus_json_obj_t   arr,
			int                idx,
			uint8_t          * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_u16(nexus_json_obj_t   arr,
			 int                idx,
			 uint16_t         * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_u32(nexus_json_obj_t   arr,
			 int                idx,
			 uint32_t         * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

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
nexus_json_array_get_u64(nexus_json_obj_t   arr,
			 int                idx,
			 uint64_t         * val)
{
    struct nx_json * tgt_obj = NULL;

    tgt_obj = nx_json_get_item(arr, idx);

    if (tgt_obj == NULL) {
	return -1;
    }
	
    if (tgt_obj->type != NX_JSON_INTEGER) {
	return -1;
    }

    *val = tgt_obj->int_value;

    return 0;
}




/* 
 * Set the value of an existing array item 
 */


int
nexus_json_array_set_string(nexus_json_obj_t   arr,
			    int                idx,
			    char             * str)
{
    struct nx_json new_val;

    new_val.type       = NX_JSON_STRING;
    new_val.text_value = str;

    return nx_json_set_item(arr, idx, &new_val);
}


int
nexus_json_array_set_bool(nexus_json_obj_t arr,
			  int              idx,
			  int              val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_BOOL;
    new_val.int_value = val;

    return nx_json_set_item(arr, idx, &new_val);    
}

int
nexus_json_array_set_int(nexus_json_obj_t arr,
			 int              idx,
			 int              val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_INTEGER;
    new_val.int_value = val;

    return nx_json_set_item(arr, idx, &new_val);    
}

int
nexus_json_array_set_double(nexus_json_obj_t arr,
			    int              idx,
			    double           val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_DOUBLE;
    new_val.dbl_value = val;

    return nx_json_set_item(arr, idx, &new_val);    
}

int
nexus_json_array_set_s64(nexus_json_obj_t arr,
			 int              idx,
			 int64_t          val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_INTEGER;
    new_val.int_value = val;

    return nx_json_set_item(arr, idx, &new_val);    
}

int
nexus_json_array_set_u64(nexus_json_obj_t arr,
			 int              idx,
			 uint64_t         val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}

int
nexus_json_array_set_s8(nexus_json_obj_t arr,
			int              idx,
			int8_t           val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}

int
nexus_json_array_set_s16(nexus_json_obj_t arr,
			 int              idx,
			 int16_t          val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}

int
nexus_json_array_set_s32(nexus_json_obj_t arr,
			 int              idx,
			 int32_t          val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}

							                  
int
nexus_json_array_set_u8(nexus_json_obj_t arr,
			int              idx,
			uint8_t          val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}

int
nexus_json_array_set_u16(nexus_json_obj_t arr,
			 int              idx,
			 uint16_t         val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}

int
nexus_json_array_set_u32(nexus_json_obj_t arr,
			 int              idx,
			 uint32_t         val)
{
    return nexus_json_array_set_s64(arr, idx, val);
}


/* 
 * Add a new item to an existing array 
 */


nexus_json_obj_t
nexus_json_array_add_object(nexus_json_obj_t arr)
{
    struct nx_json new_val;

    int idx = 0;
    
    new_val.type       = NX_JSON_OBJECT;

    idx = nx_json_add_item(arr, &new_val);

    return nx_json_get_item(arr, idx);
   
}

int
nexus_json_array_add_string(nexus_json_obj_t   arr,
			    char             * str)
{
    struct nx_json new_val;

    new_val.type       = NX_JSON_STRING;
    new_val.text_value = str;

    return nx_json_add_item(arr, &new_val);
}


int
nexus_json_array_add_bool(nexus_json_obj_t arr,
			  int              val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_BOOL;
    new_val.int_value = val;

    return nx_json_add_item(arr, &new_val);    
}

int
nexus_json_array_add_int(nexus_json_obj_t arr,
			 int              val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_INTEGER;
    new_val.int_value = val;

    return nx_json_add_item(arr, &new_val);    
}

int
nexus_json_array_add_double(nexus_json_obj_t arr,
			    double           val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_DOUBLE;
    new_val.dbl_value = val;

    return nx_json_add_item(arr, &new_val);    
}

int
nexus_json_array_add_s64(nexus_json_obj_t arr,
			 int64_t          val)
{
    struct nx_json new_val;

    new_val.type      = NX_JSON_INTEGER;
    new_val.int_value = val;

    return nx_json_add_item(arr, &new_val);    
}

int
nexus_json_array_add_u64(nexus_json_obj_t arr,
			 uint64_t         val)
{
    return nexus_json_array_add_s64(arr, val);
}

int
nexus_json_array_add_s8(nexus_json_obj_t arr,
			int8_t           val)
{
    return nexus_json_array_add_s64(arr, val);
}

int
nexus_json_array_add_s16(nexus_json_obj_t arr,
			 int16_t          val)
{
    return nexus_json_array_add_s64(arr, val);
}

int
nexus_json_array_add_s32(nexus_json_obj_t arr,
			 int32_t          val)
{
    return nexus_json_array_add_s64(arr, val);
}

							                  
int
nexus_json_array_add_u8(nexus_json_obj_t arr,
			uint8_t          val)
{
    return nexus_json_array_add_s64(arr, val);
}

int
nexus_json_array_add_u16(nexus_json_obj_t arr,
			 uint16_t         val)
{
    return nexus_json_array_add_s64(arr, val);
}

int
nexus_json_array_add_u32(nexus_json_obj_t arr,
			 uint32_t         val)
{
    return nexus_json_array_add_s64(arr, val);
}





/* Delete an array item at index idx */
int
nexus_json_array_del_idx(nexus_json_obj_t arr,
			 int              idx)
{
    nx_json_del_item(arr, idx);
    return 0;
}


int
nexus_json_array_del_item(nexus_json_obj_t arr,
			  nexus_json_obj_t item)
{
    nx_json_free(item);
    return 0;
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

