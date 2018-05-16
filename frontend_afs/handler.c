#include <stdlib.h>

#include "internal.h"

#include <nexus.h>
#include <nexus_log.h>
#include <nexus_json.h>

static const char * generic_success_rsp_str = "\"code\" : 0, \"nexus_name\" : \"%s\"";

static char *
__get_nexus_abspath(char * afs_fullpath)
{
    // XXX: duplicate string?

    return (afs_fullpath + datastore_pathlen);
}

static void
__get_nexus_dirpath(const char * filepath, char ** dirpath, char ** filename)
{
    char * fname = NULL;

    const char * nexus_abspath = filepath + datastore_pathlen;

    fname = strrchr(nexus_abspath, '/');

    if (fname == NULL) {
        *filename = strndup(nexus_abspath, PATH_MAX);
        *dirpath = strndup("", PATH_MAX);
    } else {
        *filename = strndup(fname + 1, PATH_MAX);
        *dirpath = strndup(nexus_abspath, (int)(fname - nexus_abspath));
    }
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

    log_trace("[%s] %s/%s -> %s\n",
              (type == NEXUS_REG ? "touch" : "mkdir"),
              dirpath,
              fname,
              nexus_name);

    ret = asprintf((char **)resp_buf, generic_success_rsp_str, nexus_name);

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

    log_trace("[delete] %s/%s -> %s\n", dirpath, fname, nexus_name);


    ret = asprintf((char **)resp_buf, generic_success_rsp_str, nexus_name);

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

    log_trace("[lookup] %s/%s -> %s\n", dirpath, fname, nexus_name);


    ret = asprintf((char **)resp_buf, generic_success_rsp_str, nexus_name);

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
            log_error("Could not parse filldir command\n");
            goto out;
        }

        dirpath    = __get_nexus_abspath(filldir_cmd[1].ptr);
        nexus_name = filldir_cmd[2].ptr;
    }


    ret = nexus_fs_filldir(mounted_volume, dirpath, nexus_name, &real_name);

    if (ret != 0) {
        goto out;
    }

    log_trace("[filldir] %s/%s (%s)\n", dirpath, nexus_name, real_name);


    ret = asprintf((char **)resp_buf, "\"code\" : 0, \"real_name\" : \"%s\"", real_name);

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

static int
handle_symlink(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param symlink_cmd[3] = { {"op",     NEXUS_JSON_U32,    {0} },
                                               {"source", NEXUS_JSON_STRING, {0} },
                                               {"target", NEXUS_JSON_STRING, {0} } };

    char * source     = NULL;
    char * target     = NULL;

    char * nexus_name = NULL;

    int ret = -1;


    {
        ret = nexus_json_get_params(json_obj, symlink_cmd, 3);

        if (ret < 0) {
            log_error("Could not parse symlink command\n");
            goto out;
        }

        source = symlink_cmd[1].ptr;
        target = symlink_cmd[2].ptr;
    }

    // perform the symlink
    {
        char * dirpath  = NULL;
        char * linkname = NULL;

        __get_nexus_dirpath(source, &dirpath, &linkname);

        ret = nexus_fs_symlink(mounted_volume, dirpath, linkname, target, &nexus_name);

        if (ret != 0) {
            log_error("symlink: dirpath=%s, linkname=%s, target=%s\n", dirpath, linkname, target);

            nexus_free(dirpath);
            nexus_free(linkname);

            goto out;
        }

        log_trace("[symlink] %s/%s -> %s (%s)\n", dirpath, linkname, target, nexus_name);

        nexus_free(dirpath);
        nexus_free(linkname);
    }

    ret = asprintf((char **)resp_buf, "\"code\" : 0, \"nexus_name\" : \"%s\"", nexus_name);

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
handle_hardlink(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param hardlink_cmd[3] = { {"op",     NEXUS_JSON_U32,    {0} },
                                                {"source", NEXUS_JSON_STRING, {0} },
                                                {"target", NEXUS_JSON_STRING, {0} } };

    char * source      = NULL;
    char * target      = NULL;

    char * nexus_name  = NULL;

    int ret = -1;


    {
        ret = nexus_json_get_params(json_obj, hardlink_cmd, 3);

        if (ret < 0) {
            log_error("Could not parse hardlink command\n");
            goto out;
        }

        source = hardlink_cmd[1].ptr;
        target = hardlink_cmd[2].ptr;
    }

    // perform the hardlink
    {
        char * link_dirpath  = NULL;
        char * link_filename = NULL;
        char * tget_dirpath  = NULL;
        char * tget_filename = NULL;

        __get_nexus_dirpath(source, &link_dirpath, &link_filename);
        __get_nexus_dirpath(target, &tget_dirpath, &tget_filename);

        ret = nexus_fs_hardlink(mounted_volume,
                                link_dirpath,
                                link_filename,
                                tget_dirpath,
                                tget_filename,
                                &nexus_name);

        log_trace("[hardlink] %s/%s -> %s/%s (%s)\n",
                  link_dirpath,
                  link_filename,
                  tget_dirpath,
                  tget_filename,
                  nexus_name);

        nexus_free(link_dirpath);
        nexus_free(link_filename);
        nexus_free(tget_dirpath);
        nexus_free(tget_filename);

        if (ret != 0) {
            log_error("hardlink: %s -> %s FAILED\n", source, target);
            goto out;
        }
    }


    ret = asprintf((char **)resp_buf, "\"code\" : 0, \"nexus_name\" : \"%s\"", nexus_name);

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
handle_rename(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param rename_cmd[5] = { {"op",     NEXUS_JSON_U32,      {0} },
                                              {"old_path", NEXUS_JSON_STRING, {0} },
                                              {"old_name", NEXUS_JSON_STRING, {0} },
                                              {"new_path", NEXUS_JSON_STRING, {0} },
                                              {"new_name", NEXUS_JSON_STRING, {0} } };

    char * old_dirpath  = NULL;
    char * old_filename = NULL;
    char * new_dirpath  = NULL;
    char * new_filename = NULL;

    char * old_nexus_name  = NULL;
    char * new_nexus_name  = NULL;

    int ret = -1;


    {
        ret = nexus_json_get_params(json_obj, rename_cmd, 5);

        if (ret < 0) {
            log_error("Could not parse rename command\n");
            goto out;
        }

        old_dirpath  = __get_nexus_abspath(rename_cmd[1].ptr);
        old_filename = rename_cmd[2].ptr;
        new_dirpath  = __get_nexus_abspath(rename_cmd[3].ptr);
        new_filename = rename_cmd[4].ptr;
    }


    ret = nexus_fs_rename(mounted_volume,
                          old_dirpath,
                          old_filename,
                          new_dirpath,
                          new_filename,
                          &old_nexus_name,
                          &new_nexus_name);

    if (ret != 0) {
        log_error("rename: %s/%s -> %s/%s FAILED\n", old_dirpath, old_filename, new_dirpath,
                    new_filename);
        goto out;
    }

    log_trace("[rename] %s/%s (%s) -> %s/%s (%s)\n",
              old_dirpath,
              old_filename,
              old_nexus_name,
              new_dirpath,
              new_filename,
              new_nexus_name);

    ret = asprintf((char **)resp_buf,
                   "\"code\" : 0, \"old_nexus_name\" : \"%s\", \"new_nexus_name\" : \"%s\"",
                   old_nexus_name,
                   new_nexus_name);

    if (ret == -1) {
	log_error("Could not create response string\n");
	goto out;
    }

    *resp_size = ret + 1;

    ret = 0;
 out:
    if (old_nexus_name) {
        nexus_free(old_nexus_name);
    }

    if (new_nexus_name) {
        nexus_free(new_nexus_name);
    }

    return ret;
}

static int
handle_encrypt(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param encrypt_cmd[5] = { { "op", NEXUS_JSON_U32, { 0 } },
                                               { "path", NEXUS_JSON_STRING, { 0 } },
                                               { "offset", NEXUS_JSON_U32, { 0 } },
                                               { "buflen", NEXUS_JSON_U32, { 0 } },
                                               { "filesize", NEXUS_JSON_U32, { 0 } } };

    char * path     = NULL;
    size_t offset   = 0;
    size_t buflen   = 0;
    size_t filesize = 0;

    int ret = -1;

    {
        ret = nexus_json_get_params(json_obj, encrypt_cmd, 5);

        if (ret < 0) {
            log_error("could not parse encrypt command\n");
            return -1;
        }

        path     = __get_nexus_abspath(encrypt_cmd[1].ptr);
        offset   = encrypt_cmd[2].val;
        buflen   = encrypt_cmd[3].val;
        filesize = encrypt_cmd[4].val;
    }

    ret = nexus_fs_encrypt(mounted_volume,
                           path,
                           global_databuf_addr,
                           global_databuf_addr,
                           offset,
                           buflen,
                           filesize);

    if (ret != 0) {
        printf("encrypting (%s) FAILED\n", path);
        return -1;
    }

    ret = asprintf((char **)resp_buf, "\"code\" : 0");

    if (ret == -1) {
	log_error("Could not create response string\n");
        return -1;
    }

    *resp_size = ret + 1;

    return 0;
}

static int
handle_decrypt(nexus_json_obj_t json_obj, uint8_t ** resp_buf, uint32_t * resp_size)
{
    struct nexus_json_param decrypt_cmd[5] = { { "op", NEXUS_JSON_U32, { 0 } },
                                               { "path", NEXUS_JSON_STRING, { 0 } },
                                               { "offset", NEXUS_JSON_U32, { 0 } },
                                               { "buflen", NEXUS_JSON_U32, { 0 } },
                                               { "filesize", NEXUS_JSON_U32, { 0 } } };

    char * path     = NULL;
    size_t offset   = 0;
    size_t buflen   = 0;
    size_t filesize = 0;

    int ret = -1;

    {
        ret = nexus_json_get_params(json_obj, decrypt_cmd, 5);

        if (ret < 0) {
            log_error("could not parse decrypt command\n");
            return -1;
        }

        path     = __get_nexus_abspath(decrypt_cmd[1].ptr);
        offset   = decrypt_cmd[2].val;
        buflen   = decrypt_cmd[3].val;
        filesize = decrypt_cmd[4].val;
    }

    ret = nexus_fs_decrypt(mounted_volume,
                           path,
                           global_databuf_addr,
                           global_databuf_addr,
                           offset,
                           buflen,
                           filesize);

    if (ret != 0) {
        printf("decrypting (%s) FAILED\n", path);
        return -1;
    }

    ret = asprintf((char **)resp_buf, "\"code\" : 0");

    if (ret == -1) {
	log_error("Could not create response string\n");
        return -1;
    }

    *resp_size = ret + 1;

    return 0;
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
        case AFS_OP_SYMLINK:
            ret = handle_symlink(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_HARDLINK:
            ret = handle_hardlink(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_RENAME:
            ret = handle_rename(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_ENCRYPT:
            ret = handle_encrypt(json_obj, resp_buf, resp_size);
            break;
        case AFS_OP_DECRYPT:
            ret = handle_decrypt(json_obj, resp_buf, resp_size);
            break;
        default:
            ret = -1;
            break;
    }

    nexus_json_free(json_obj);

    return ret;
}
