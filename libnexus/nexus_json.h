#pragma once



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




int
nexus_json_get_params(nexus_json_obj_t          obj,
		      struct nexus_json_param * params,
		      uint32_t                  num_params);


nexus_json_obj_t
nexus_json_parse_str(char * str);

nexus_json_obj_t
nexus_json_parse_file(char * file_name);


nexus_json_obj_t
nexus_json_parse_file(char * str);

void
nexus_json_free_object(nexus_json_obj_t object);





nexus_json_obj_t nexus_json_get_object(nexus_json_obj_t obj, char * key);
int              nexus_json_add_object(nexus_json_obj_t obj, char * key);
int              nexus_json_del_object(nexus_json_obj_t obj);


int nexus_json_del(nexus_json_obj_t obj, char * key);


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





char *
nexus_json_serialize(nexus_json_obj_t obj);
