#pragma once

typedef enum {
    NEXUS_JSON_U8,
    NEXUS_JSON_S8,
    NEXUS_JSON_U16,
    NEXUS_JSON_S16,
    NEXUS_JSON_U32,
    NEXUS_JSON_S32,
    NEXUS_JSON_U64,
    NEXUS_JSON_S64,
    NEXUS_JSON_STRING
} nexus_json_type_t;


struct nexus_json_param {
    char              * name;

    nexus_json_type_t   type;
    
    union {
	uintptr_t           val;    
	void             *  ptr;
    };
};



/* A simple parser with basic validation but limited JSON support
 * Currently only handles basic 'key : value' pairs. 
 *  
 * Does not handle objects. i.e. the use of '{}'s in the string. 
 * Does not handle arrays
 * 
 * Extending it is possible, but for now it does what we need.
 */

int
nexus_json_parse(char                    * str,
		 struct nexus_json_param * params,
		 uint32_t                  num_params);

int
nexus_json_release_params(struct nexus_json_param * params,
			  uint32_t                  num_params);
