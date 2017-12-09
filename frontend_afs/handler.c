#include <stdlib.h>


#include "afs.h"
#include "handler.h"

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_json.h>

static int
handle_create(uint8_t *  cmd_buf,
              uint32_t   cmd_size,
              uint8_t ** resp_buf,
              uint32_t * resp_size)
{
    struct nexus_json_param create_cmd[4] = { {"op",   NEXUS_JSON_U32,    {0} },
					      {"name", NEXUS_JSON_STRING, {0} },
					      {"path", NEXUS_JSON_STRING, {0} },
					      {"type", NEXUS_JSON_U32,    {0} } };

    char * nexus_name = NULL;
    
    int ret = -1;

    
    ret = nexus_json_get_params((char *)cmd_buf, create_cmd, 4);

    if (ret < 0) {
	log_error("Could not parse lookup command (%s)\n", cmd_buf);
	goto out;
    }


    /* Handle Lookup */
    ret = nexus_new(create_cmd[2].ptr, create_cmd[1].ptr, create_cmd[3].val, &nexus_name);

    ret = asprintf((char **)resp_buf, "code : %d, nexus_name : \"%s\"", ret, nexus_name);
	
    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;
    
    ret = 0;
	
 out:
    
    return ret;
	
}

static int
handle_remove(uint8_t *  cmd_buf,
              uint32_t   cmd_size,
              uint8_t ** resp_buf,
              uint32_t * resp_size)
{
    struct nexus_json_param remove_cmd[4] = { {"op",   NEXUS_JSON_U32,    {0} },
					      {"name", NEXUS_JSON_STRING, {0} },
					      {"path", NEXUS_JSON_STRING, {0} },
					      {"type", NEXUS_JSON_U32,    {0} } };

    char * nexus_name = NULL;
    
    int ret = -1;

    
    ret = nexus_json_get_params((char *)cmd_buf, remove_cmd, 4);

    if (ret < 0) {
	log_error("Could not parse lookup command (%s)\n", cmd_buf);
	goto out;
    }


    /* Handle Lookup */
    ret = nexus_remove(
        remove_cmd[2].ptr, remove_cmd[1].ptr, remove_cmd[3].val, &nexus_name);

    ret = asprintf((char **)resp_buf, "code : %d, nexus_name : \"%s\"", ret, nexus_name);
	
    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;
    
    ret = 0;
	
 out:
    
    return ret;
	
}

static int
handle_lookup(uint8_t   * cmd_buf,
	      uint32_t    cmd_size,
	      uint8_t  ** resp_buf,
	      uint32_t  * resp_size)
{
    struct nexus_json_param lookup_cmd[4] = { {"op",   NEXUS_JSON_U32,    {0} },
					      {"name", NEXUS_JSON_STRING, {0} },
					      {"path", NEXUS_JSON_STRING, {0} },
					      {"type", NEXUS_JSON_U32,    {0} } };

    char * nexus_name = NULL;
    
    int ret = -1;

    
    ret = nexus_json_get_params((char *)cmd_buf, lookup_cmd, 4);

    if (ret < 0) {
	log_error("Could not parse lookup command (%s)\n", cmd_buf);
	goto out;
    }

    /* Handle Lookup */
    ret = nexus_lookup(lookup_cmd[2].ptr, lookup_cmd[1].ptr, lookup_cmd[3].val, &nexus_name);

    ret = asprintf((char **)resp_buf, "code : %d, nexus_name : \"%s\"", ret, nexus_name);
	
    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;
    
    ret = 0;
	
 out:
    
    return ret;
	
}

static int
handle_filldir(uint8_t   * cmd_buf,
	       uint32_t    cmd_size,
	       uint8_t  ** resp_buf,
	       uint32_t  * resp_size)
{
    struct nexus_json_param filldir_cmd[4] = { {"op",         NEXUS_JSON_U32,    {0} },
					       {"path",       NEXUS_JSON_STRING, {0} },
					       {"nexus_name", NEXUS_JSON_STRING, {0} },
					       {"type",       NEXUS_JSON_U32,    {0} } };

    char * real_name = NULL;

    int ret = -1;

    ret = nexus_json_get_params((char *)cmd_buf, filldir_cmd, 4);

    if (ret < 0) {
	log_error("Could not parse filldir command (%s)\n", cmd_buf);
	goto out;
    }

    /* Handle Lookup */
    ret = nexus_filldir(filldir_cmd[1].ptr, filldir_cmd[2].ptr, filldir_cmd[3].val, &real_name);

    ret = asprintf((char **)resp_buf, "code : %d, real_name : \"%s\"", ret, real_name);
	
    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;
    
    ret = 0;
	
 out:
    
    return ret;


}

    

int
dispatch_nexus_command(uint8_t   * cmd_buf,
		       uint32_t    cmd_size,
		       uint8_t  ** resp_buf,
		       uint32_t  * resp_size)
{
    struct nexus_json_param op_code = {"op", NEXUS_JSON_U32, {0}};

    int    ret      = 0;

    ret = nexus_json_get_params((char *)cmd_buf, &op_code, 1);

    if (ret < 0) {
	log_error("Error parsing nexus command\n");
	return -1;
    }
    

    switch (op_code.val) {
	case AFS_OP_CREATE:
	    ret = handle_create(cmd_buf, cmd_size, resp_buf, resp_size);
            break;
        case AFS_OP_REMOVE:
            ret = handle_remove(cmd_buf, cmd_size, resp_buf, resp_size);
            break;
        case AFS_OP_LOOKUP:
	    ret = handle_lookup(cmd_buf, cmd_size, resp_buf, resp_size);
	    break;
	case AFS_OP_FILLDIR:
	    ret = handle_filldir(cmd_buf, cmd_size, resp_buf, resp_size);
	    break;
	default:
	    ret = -1;
	    break;
    }
    
    
    
    return ret;
}
