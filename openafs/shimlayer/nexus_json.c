#include <linux/kernel.h>

#include "nexus_util.h"
#include "nexus_json.h"
#include "nexus_jsmn.h"

int
nexus_json_parse(char                    * str,
		 struct nexus_json_param * params,
		 u32                       num_params)
{
    jsmn_parser   parser;
    jsmntok_t   * tokens     = NULL;

    int num_tokens = (2 * num_params);
    int ret        = -1;
    int i          = 0;
    
    /* Initialize JSMN parser */
    jsmn_init(&parser);

    /* Allocate tokens */
    tokens = nexus_kmalloc(sizeof(jsmntok_t) * num_tokens, GFP_KERNEL);

    if (tokens == NULL) {
	NEXUS_ERROR("Could not allocate JSMN tokens\n");
	goto out;
    }

    memset(tokens, 0, sizeof(jsmntok_t) * num_tokens);
    

    /* Parse JSON */
    ret = jsmn_parse(&parser, str, strlen(str), tokens, num_tokens);

    if (ret != 0) {
	NEXUS_ERROR("JSON Parse error\n");
	goto out;
    }


    /* Null terminate all tokens */
    for (i = 0; i < num_tokens; i++) {
	str[tokens[i].end] = '\0';
    }

    
    /* Check Params and grab values */
    for (i = 0; i < num_params; i++) {

	jsmntok_t * name_tok = &(tokens[(i * 2)]);
	jsmntok_t *  val_tok = &(tokens[(i * 2) + 1]);
	
	char * name  = str + name_tok->start;
	char * value = str +  val_tok->start;
	
	if (strncmp(params[i].name, name, strlen(params[i].name)) != 0) {
	    NEXUS_ERROR("Erro matching JSON format\n");
	    goto out;
	}	

	switch (params[i].type) {
	    case NEXUS_JSON_U8:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou8(value, 0, (u8 *)&(params[i].val));

		break;
	    case NEXUS_JSON_S8:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtos8(value, 0, (s8 *)&(params[i].val));

		break;
	    case NEXUS_JSON_U16:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou16(value, 0, (u16 *)&(params[i].val));

		break;
	    case NEXUS_JSON_S16:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtos16(value, 0, (s16 *)&(params[i].val));

		break;
	    case NEXUS_JSON_U32:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou32(value, 0, (u32 *)&(params[i].val));

		break;
	    case NEXUS_JSON_S32:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;

		}
		
		ret = kstrtos32(value, 0, (s32 *)&(params[i].val));

		break;
	    case NEXUS_JSON_U64:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou64(value, 0, (u64 *)&(params[i].val));


		break;
	    case NEXUS_JSON_S64:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtos64(value, 0, (s64 *)&(params[i].val));

		break;
	    case NEXUS_JSON_STRING:
		if (val_tok->type != JSMN_STRING) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret           = 0;
		params[i].val = (uintptr_t)value;
		
		break;
	    default:
		NEXUS_ERROR("Error Invalid Parameter Type (%d)\n", params[i].type);
		goto out;
	}
	

    }

    if (ret != 0) {
	NEXUS_ERROR("Error Parsing JSON value\n");
    }


 out:
    if (tokens) nexus_kfree(tokens);

    return ret;

}
		 
