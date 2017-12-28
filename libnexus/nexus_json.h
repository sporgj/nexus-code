/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#pragma once

#include <stdint.h>

#define NEXUS_JSON_INVALID_OBJ (NULL)

typedef void * nexus_json_obj_t;

typedef enum {
    NEXUS_JSON_U8,
    NEXUS_JSON_S8,
    NEXUS_JSON_U16,
    NEXUS_JSON_S16,
    NEXUS_JSON_U32,
    NEXUS_JSON_S32,
    NEXUS_JSON_U64,
    NEXUS_JSON_S64,
    NEXUS_JSON_STRING,
    NEXUS_JSON_OBJECT
} nexus_json_type_t;


struct nexus_json_param {
    char              * name;

    nexus_json_type_t   type;
    
    union {
	uintptr_t           val;    
	void             *  ptr;
    };
};


/* Batch query for a set of parameters */
int
nexus_json_get_params(nexus_json_obj_t          obj,
		      struct nexus_json_param * params,
		      uint32_t                  num_params);



nexus_json_obj_t nexus_json_new_obj(char * key);
nexus_json_obj_t nexus_json_new_arr(char * key);

int nexus_json_splice(nexus_json_obj_t   parent,
		      nexus_json_obj_t   obj);

int nexus_json_split(nexus_json_obj_t obj);

nexus_json_obj_t nexus_json_parse_str(char * str);
nexus_json_obj_t nexus_json_parse_file(char * file_name);



char * nexus_json_serialize(nexus_json_obj_t obj);
int    nexus_json_serialize_to_file(nexus_json_obj_t obj, char * filename);



/* Free a parsed JSON structure */
void nexus_json_free(nexus_json_obj_t object);



/* 
 * Object Accessors 
 */

nexus_json_obj_t nexus_json_add_object(nexus_json_obj_t obj, char * key);
nexus_json_obj_t nexus_json_get_object(nexus_json_obj_t obj, char * key);
int              nexus_json_del_object(nexus_json_obj_t obj);


/* 
 * Object Member Accessors 
 */

/* Return a parameter from the JSON tree */
int nexus_json_get_string(nexus_json_obj_t obj, char * key, char    ** val);

int nexus_json_get_bool  (nexus_json_obj_t obj, char * key, int      * val);
int nexus_json_get_int   (nexus_json_obj_t obj, char * key, int      * val);
int nexus_json_get_double(nexus_json_obj_t obj, char * key, double   * val);

int nexus_json_get_s8    (nexus_json_obj_t obj, char * key, int8_t   * val);
int nexus_json_get_s16   (nexus_json_obj_t obj, char * key, int16_t  * val);
int nexus_json_get_s32   (nexus_json_obj_t obj, char * key, int32_t  * val);
int nexus_json_get_s64   (nexus_json_obj_t obj, char * key, int64_t  * val);

int nexus_json_get_u8    (nexus_json_obj_t obj, char * key, uint8_t  * val);
int nexus_json_get_u16   (nexus_json_obj_t obj, char * key, uint16_t * val);
int nexus_json_get_u32   (nexus_json_obj_t obj, char * key, uint32_t * val);
int nexus_json_get_u64   (nexus_json_obj_t obj, char * key, uint64_t * val);

/* Set the values of currently existing parameters */
int nexus_json_set_string(nexus_json_obj_t obj, char * key, char * str);  
							                  
int nexus_json_set_bool  (nexus_json_obj_t obj, char * key, int      val);
int nexus_json_set_int   (nexus_json_obj_t obj, char * key, int      val);
int nexus_json_set_double(nexus_json_obj_t obj, char * key, double   val);
							                  
int nexus_json_set_s8    (nexus_json_obj_t obj, char * key, int8_t   val);
int nexus_json_set_s16   (nexus_json_obj_t obj, char * key, int16_t  val);
int nexus_json_set_s32   (nexus_json_obj_t obj, char * key, int32_t  val);
int nexus_json_set_s64   (nexus_json_obj_t obj, char * key, int64_t  val);
							                  
int nexus_json_set_u8    (nexus_json_obj_t obj, char * key, uint8_t  val);
int nexus_json_set_u16   (nexus_json_obj_t obj, char * key, uint16_t val);
int nexus_json_set_u32   (nexus_json_obj_t obj, char * key, uint32_t val);
int nexus_json_set_u64   (nexus_json_obj_t obj, char * key, uint64_t val);


/* Add new parameters to the JSON tree */
int nexus_json_add_string(nexus_json_obj_t obj, char * key, char * str);  
							                  
int nexus_json_add_bool  (nexus_json_obj_t obj, char * key, int      val);
int nexus_json_add_int   (nexus_json_obj_t obj, char * key, int      val);
int nexus_json_add_double(nexus_json_obj_t obj, char * key, double   val);
							                  
int nexus_json_add_s8    (nexus_json_obj_t obj, char * key, int8_t   val);
int nexus_json_add_s16   (nexus_json_obj_t obj, char * key, int16_t  val);
int nexus_json_add_s32   (nexus_json_obj_t obj, char * key, int32_t  val);
int nexus_json_add_s64   (nexus_json_obj_t obj, char * key, int64_t  val);
							                  
int nexus_json_add_u8    (nexus_json_obj_t obj, char * key, uint8_t  val);
int nexus_json_add_u16   (nexus_json_obj_t obj, char * key, uint16_t val);
int nexus_json_add_u32   (nexus_json_obj_t obj, char * key, uint32_t val);
int nexus_json_add_u64   (nexus_json_obj_t obj, char * key, uint64_t val);

/* Delete a parameter */
int nexus_json_del_by_key(nexus_json_obj_t obj, char * key);


/* 
 * Array Accessors 
 */

nexus_json_obj_t nexus_json_add_array(nexus_json_obj_t obj, char * key);
nexus_json_obj_t nexus_json_get_array(nexus_json_obj_t obj, char * key);
int              nexus_json_del_array(nexus_json_obj_t arr);

int              nexus_json_get_array_len(nexus_json_obj_t arr);


nexus_json_obj_t nexus_json_array_get_object(nexus_json_obj_t arr, int idx);
nexus_json_obj_t nexus_json_array_add_object(nexus_json_obj_t arr);


/* 
 * Array Item Accessors
 */

/* Get an array item  */

int nexus_json_array_get_string(nexus_json_obj_t arr, int idx, char    ** val);

int nexus_json_array_get_bool  (nexus_json_obj_t arr, int idx, int      * val);
int nexus_json_array_get_int   (nexus_json_obj_t arr, int idx, int      * val);
int nexus_json_array_get_double(nexus_json_obj_t arr, int idx, double   * val);

int nexus_json_array_get_s8    (nexus_json_obj_t arr, int idx, int8_t   * val);
int nexus_json_array_get_s16   (nexus_json_obj_t arr, int idx, int16_t  * val);
int nexus_json_array_get_s32   (nexus_json_obj_t arr, int idx, int32_t  * val);
int nexus_json_array_get_s64   (nexus_json_obj_t arr, int idx, int64_t  * val);

int nexus_json_array_get_u8    (nexus_json_obj_t arr, int idx, uint8_t  * val);
int nexus_json_array_get_u16   (nexus_json_obj_t arr, int idx, uint16_t * val);
int nexus_json_array_get_u32   (nexus_json_obj_t arr, int idx, uint32_t * val);
int nexus_json_array_get_u64   (nexus_json_obj_t arr, int idx, uint64_t * val);

/* Set the value of an existing array item */
int nexus_json_array_set_string(nexus_json_obj_t arr, int idx, char     * val);

int nexus_json_array_set_bool  (nexus_json_obj_t arr, int idx, int        val);
int nexus_json_array_set_int   (nexus_json_obj_t arr, int idx, int        val);
int nexus_json_array_set_double(nexus_json_obj_t arr, int idx, double     val);

int nexus_json_array_set_s8    (nexus_json_obj_t arr, int idx, int8_t     val);
int nexus_json_array_set_s16   (nexus_json_obj_t arr, int idx, int16_t    val);
int nexus_json_array_set_s32   (nexus_json_obj_t arr, int idx, int32_t    val);
int nexus_json_array_set_s64   (nexus_json_obj_t arr, int idx, int64_t    val);

int nexus_json_array_set_u8    (nexus_json_obj_t arr, int idx, uint8_t    val);
int nexus_json_array_set_u16   (nexus_json_obj_t arr, int idx, uint16_t   val);
int nexus_json_array_set_u32   (nexus_json_obj_t arr, int idx, uint32_t   val);
int nexus_json_array_set_u64   (nexus_json_obj_t arr, int idx, uint64_t   val);

/* Add a new array item */

int nexus_json_array_add_string(nexus_json_obj_t arr, char     * val);

int nexus_json_array_add_bool  (nexus_json_obj_t arr, int        val);
int nexus_json_array_add_int   (nexus_json_obj_t arr, int        val);
int nexus_json_array_add_double(nexus_json_obj_t arr, double     val);

int nexus_json_array_add_s8    (nexus_json_obj_t arr, int8_t     val);
int nexus_json_array_add_s16   (nexus_json_obj_t arr, int16_t    val);
int nexus_json_array_add_s32   (nexus_json_obj_t arr, int32_t    val);
int nexus_json_array_add_s64   (nexus_json_obj_t arr, int64_t    val);

int nexus_json_array_add_u8    (nexus_json_obj_t arr, uint8_t    val);
int nexus_json_array_add_u16   (nexus_json_obj_t arr, uint16_t   val);
int nexus_json_array_add_u32   (nexus_json_obj_t arr, uint32_t   val);
int nexus_json_array_add_u64   (nexus_json_obj_t arr, uint64_t   val);

/* Delete an array item */
int nexus_json_array_del_idx   (nexus_json_obj_t arr, int idx);
int nexus_json_array_del_item  (nexus_json_obj_t arr, nexus_json_obj_t item);




/* Array iteration 
 * @iter: (nexus_json_obj_t) - iterator variable
 * @arr:  (nexus_json_obj_t) - array to iterate through
 */
#include "nxjson.h"
#define nexus_json_arr_foreach(iter, arr)			\
    for ((iter) = ((struct nx_json *)(arr))->child; (iter) != NULL; (iter) = ((struct nx_json *)(iter))->next)
