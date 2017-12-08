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





nexus_json_obj_t 
nexus_json_get_object(nexus_json_obj_t   obj,
		      char             * key);

char *
nexus_json_get_string(nexus_json_obj_t   obj,
		      char             * key);

