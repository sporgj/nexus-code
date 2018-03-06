#include <stdlib.h>

#include "internal.h"

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_json.h>

static const char * generic_success_rsp_str = "code : %d, nexus_name : \"%s\"";

static char *
__get_nexus_abspath(char * afs_fullpath)
{
    // XXX: duplicate string?

    return (afs_fullpath + datastore_pathlen);
}

static int
handle_create(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param create_cmd[4] = { {"op",   NEXUS_JSON_U32,    {0} },
                                              {"name", NEXUS_JSON_STRING, {0} },
                                              {"path", NEXUS_JSON_STRING, {0} },
                                              {"type", NEXUS_JSON_U32,    {0} } };

    char * dirpath    = NULL;
    char * fname      = NULL;
    nexus_dirent_type_t type;

    char * nexus_name = NULL;

    int ret = -1;


    {
        ret = nexus_json_get_params(json_obj, create_cmd, 4);

        if (ret < 0) {
            log_error("Could not parse create command\n");
            goto out;
        }

        fname   = create_cmd[1].ptr;
        dirpath = __get_nexus_abspath(create_cmd[2].ptr);
        type    = create_cmd[3].val;
    }

    ret = nexus_fs_touch(mounted_volume, dirpath, fname, type, &nexus_name);

    if (ret != 0) {
        log_error("creating %s/%s FAILED\n", (char *)create_cmd[2].ptr, fname);
        goto out;
    }


    ret = asprintf((char **)resp_buf, generic_success_rsp_str, ret, nexus_name);

    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;

    ret = 0;
 out:
    if (nexus_name) {
        nexus_free(nexus_name);
    }

    return ret;
}

static int
handle_remove(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param remove_cmd[4] = { {"op",   NEXUS_JSON_U32,    {0} },
                                              {"name", NEXUS_JSON_STRING, {0} },
                                              {"path", NEXUS_JSON_STRING, {0} },
                                              {"type", NEXUS_JSON_U32,    {0} } };

    char * dirpath    = NULL;
    char * fname      = NULL;
    char * nexus_name = NULL;

    int ret = -1;


    {
        ret = nexus_json_get_params(json_obj, remove_cmd, 4);

        if (ret < 0) {
            log_error("Could not parse remove command\n");
            goto out;
        }

        fname   = remove_cmd[1].ptr;
        dirpath = __get_nexus_abspath(remove_cmd[2].ptr);
    }


    ret = nexus_fs_remove(mounted_volume, dirpath, fname, &nexus_name);

    if (ret != 0) {
        log_error("removing %s/%s FAILED\n", (char *)remove_cmd[2].ptr, fname);
        goto out;
    }


    ret = asprintf((char **)resp_buf, generic_success_rsp_str, ret, nexus_name);

    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;

    ret = 0;
 out:
    if (nexus_name) {
        nexus_free(nexus_name);
    }

    return ret;
}

static int
handle_lookup(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param lookup_cmd[4] = { {"op",   NEXUS_JSON_U32,    {0} },
                                              {"name", NEXUS_JSON_STRING, {0} },
                                              {"path", NEXUS_JSON_STRING, {0} },
                                              {"type", NEXUS_JSON_U32,    {0} } };
    char * dirpath    = NULL;
    char * fname      = NULL;
    char * nexus_name = NULL;

    int ret = -1;


    {
        ret = nexus_json_get_params(json_obj, lookup_cmd, 4);

        if (ret < 0) {
            log_error("Could not parse lookup command\n");
            goto out;
        }

        fname   = lookup_cmd[1].ptr;
        dirpath = __get_nexus_abspath(lookup_cmd[2].ptr);
    }


    ret = nexus_fs_lookup(mounted_volume, dirpath, fname, &nexus_name);

    if (ret != 0) {
        goto out;
    }


    ret = asprintf((char **)resp_buf, generic_success_rsp_str, ret, nexus_name);

    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;

    ret = 0;
 out:
    if (nexus_name) {
        nexus_free(nexus_name);
    }

    return ret;
}

static int
handle_filldir(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param filldir_cmd[4] = { {"op",         NEXUS_JSON_U32,    {0} },
                                               {"path",       NEXUS_JSON_STRING, {0} },
                                               {"nexus_name", NEXUS_JSON_STRING, {0} },
                                               {"type",       NEXUS_JSON_U32,    {0} } };

    char * dirpath    = NULL;
    char * nexus_name = NULL;

    char * real_name = NULL;

    int ret = -1;

    {
        ret = nexus_json_get_params(json_obj, filldir_cmd, 4);

        if (ret < 0) {
            log_error("Could not parse create command\n");
            goto out;
        }

        dirpath    = __get_nexus_abspath(filldir_cmd[1].ptr);
        nexus_name = filldir_cmd[2].ptr;
    }


    ret = nexus_fs_filldir(mounted_volume, dirpath, nexus_name, &real_name);

    if (ret != 0) {
        goto out;
    }


    ret = asprintf((char **)resp_buf, "code : %d, real_name : \"%s\"", ret, real_name);

    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;

    ret = 0;
 out:
    if (real_name) {
        nexus_free(real_name);
    }

    return ret;
}

int
dispatch_nexus_command(uint8_t   * cmd_buf,
                       uint32_t    cmd_size,
                       uint8_t  ** resp_buf,
                       uint32_t  * resp_size)
{
    nexus_json_obj_t json_obj;

    struct nexus_json_param op_code = {"op", NEXUS_JSON_U32, {0}};

    int    ret      = 0;


    json_obj = nexus_json_parse_str((char *)cmd_buf);
    if (json_obj == NEXUS_JSON_INVALID_OBJ) {
        log_error("could not parse JSON\n");
        return -1;
    }

    ret = nexus_json_get_params(json_obj, &op_code, 1);

    if (ret < 0) {
        nexus_json_free(json_obj);

	log_error("Error parsing nexus command\n");
	return -1;
    }

    switch (op_code.val) {
	case AFS_OP_CREATE:
            ret = handle_create(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_REMOVE:
            ret = handle_remove(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_LOOKUP:
            ret = handle_lookup(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_FILLDIR:
            ret = handle_filldir(json_obj, resp_buf, resp_size);
            break;
        default:
            ret = -1;
            break;
    }

    nexus_json_free(json_obj);

    return ret;
}
