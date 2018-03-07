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

    int param_overflow = 0;
    int num_tokens     = (2 * num_params);
    int ret            = -1;
    int i              = 0;

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

    if (ret == JSMN_ERROR_NOMEM) {
        param_overflow = 1;
    } else if (ret < 0) {
	NEXUS_ERROR("JSON Parse error\n");
	goto out;
    }


    /* Check Params and grab values */
    for (i = 0; i < num_params; i++) {

	jsmntok_t * name_tok = &(tokens[(i * 2)]);
	jsmntok_t *  val_tok = &(tokens[(i * 2) + 1]);

	char * name  = str + name_tok->start;
	char * value = str +  val_tok->start;

	if (strncmp(params[i].name, name, strlen(params[i].name)) != 0) {
            // JBD: Because messages from userspace only need to specify the
            // exit code on FAILURE, this will print waay to often (e.g. failed lookups)
            //
            // NEXUS_ERROR("Error matching JSON format\n");
            goto out;
        }

        switch (params[i].type) {
	    case NEXUS_JSON_U8:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou8(value, 0, (u8 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_U8 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_S8:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtos8(value, 0, (s8 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_S8 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_U16:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou16(value, 0, (u16 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_U16 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_S16:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtos16(value, 0, (s16 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_S16 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_U32:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou32(value, 0, (u32 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_U32 Conversion error\n");
                    goto out;
                }

		break;
	    case NEXUS_JSON_S32:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;

		}
		
		ret = kstrtos32(value, 0, (s32 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_S32 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_U64:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtou64(value, 0, (u64 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_U64 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_S64:
		if (val_tok->type != JSMN_PRIMITIVE) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		ret = kstrtos64(value, 0, (s64 *)&(params[i].val));

		if (ret == -1) {
                    NEXUS_ERROR("NEXUS_JSON_S64 Conversion error\n");
                    goto out;
                }
		
		break;
	    case NEXUS_JSON_STRING: {
		int tmp_len = val_tok->end - val_tok->start;
		
		if (val_tok->type != JSMN_STRING) {
		    NEXUS_ERROR("JSON Error: type mismatch\n");
		    goto out;
		}

		params[i].ptr = kzalloc(tmp_len + 1, GFP_KERNEL);
		strncpy(params[i].ptr, value, tmp_len);
		
		break;
	    }
	    default:
		NEXUS_ERROR("Error Invalid Parameter Type (%d)\n", params[i].type);
		goto out;
	}
	

    }


    if (param_overflow) {
        ret = 1;
    } else {
        ret = 0;
    }

 out:

    if (tokens) nexus_kfree(tokens);

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
            nexus_kfree(params[i].val);
        }
    }
    
    return 0;
}
