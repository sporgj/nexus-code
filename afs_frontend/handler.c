#include <stdlib.h>


#include "afs.h"
#include "handler.h"

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_json.h>



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

    
    ret = nexus_json_parse((char *)cmd_buf, lookup_cmd, 4);

    if (ret < 0) {
	log_error("Could not parse lookup command (%s)\n", cmd_buf);
	goto out;
    }


    log_debug("Parsed Lookup Command:\n");
    log_debug("Op   = %u\n", (uint32_t)lookup_cmd[0].val);
    log_debug("name = %s\n", (char *)  lookup_cmd[1].ptr);
    log_debug("path = %s\n", (char *)  lookup_cmd[2].ptr);
    log_debug("type = %u\n", (uint32_t)lookup_cmd[3].val);


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
    
    nexus_json_release_params(lookup_cmd, 4);
    
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

    ret = nexus_json_parse((char *)cmd_buf, filldir_cmd, 4);

    if (ret < 0) {
	log_error("Could not parse filldir command (%s)\n", cmd_buf);
	goto out;
    }


    log_debug("Parsed Filldir Command:\n");
    log_debug("Op         = %u\n", (uint32_t)lookup_cmd[0].val);
    log_debug("path       = %s\n", (char *)  lookup_cmd[1].ptr);
    log_debug("nexus_name = %s\n", (char *)  lookup_cmd[2].ptr);
    log_debug("type       = %u\n", (uint32_t)lookup_cmd[3].val);


    /* Handle Lookup */
    ret = nexus_lookup(filldir_cmd[1].ptr, filldir_cmd[2].ptr, filldir_cmd[3].val, &real_name);

    ret = asprintf((char **)resp_buf, "code : %d, real_name : \"%s\"", ret, real_name);
	
    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;
    
    ret = 0;
	
 out:
    
    nexus_json_release_params(filldir_cmd, 4);
    
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

    ret = nexus_json_parse((char *)cmd_buf, &op_code, 1);

    if (ret < 0) {
	log_error("Error parsing nexus command\n");
	return -1;
    }
    

    printf("Handling Command %u\n", (uint32_t)op_code.val);
    
    switch (op_code.val) {
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


    printf("Command handler returned %d\n", ret);

    nexus_json_release_params(&op_code, 1);
    
    
    
    return ret;
}
