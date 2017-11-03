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
    uintptr_t           val;    
};


int
nexus_json_parse(char                    * str,
		 struct nexus_json_param * params,
		 u32                       num_params);
