#include <string.h>

#include "types.h"
#include "uc_dirops.h"
#include "uc_dnode.h"
#include "uc_dcache.h"

#include "uc_uspace.h"
#include "encode.h"
#include "uc_utils.h"
#include "slog.h"
#include "hashmap.h"

static map_t encoded_to_raw_table = NULL;

int dirops_new(const char * fpath, ucafs_entry_type type,
               char ** encoded_name_dest)
{
    int error = -1; // TODO change this
    char * fname = do_get_fname(fpath), *temp;
    struct dirnode * dirnode = NULL, *dirnode1 = NULL;
    const encoded_fname_t * fname_code = NULL;
    sds path1 = NULL;

    if (fname == NULL) {
        slog(0, SLOG_ERROR, "Error getting file name: %s", fpath);
        goto out;
    }

    /* lets get the directory entry */
    if ((dirnode = dcache_get(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Error loading dirnode: %s", fpath);
        goto out;
    }

    /* Get filename and add it to DirNode */
    if ((fname_code = dirnode_add(dirnode, fname, type)) == NULL) {
        slog(0, SLOG_ERROR, "Add file operation failed: %s", fpath);
        goto out;
    }

    // 3 - Flush to disk
    if (!dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "Flushing '%s' failed", fpath);
        goto out;
    }

    temp = encode_bin2str(fname_code);

    if (type == UCAFS_TYPE_DIR) {
        dirnode1 = dirnode_new();
        path1 = uc_get_dnode_path(temp);
        if (!dirnode_write(dirnode1, path1)) {
            slog(0, SLOG_ERROR, "Creating: '%s' dirnode failed", fpath);
            goto out;
        }
    } else if (type == UCAFS_TYPE_FILE) {
        /* TODO: create filebox object */
    }

    /* Set the encoded name */
    *encoded_name_dest = temp;
    error = 0;
out:
    if (dirnode)
        dcache_put(dirnode);
    if (dirnode1)
        dcache_put(dirnode1);
    if (fname)
        sdsfree(fname);
    if (path1)
        sdsfree(path1);
    if (fname_code)
        free((void *)fname_code);

    return error;

}

int dirops_code2plain(char * encoded_name, char * dir_path,
                      ucafs_entry_type type, char ** raw_name_dest)
{
    int error = -1; // TODO
    encoded_fname_t * fname_code = NULL;
    const char * result;

    /* 1 - Get the binary version */
    if ((fname_code = encode_str2bin(encoded_name)) == NULL) {
        return -1;
    }

    // 2 - Get the corresponding dirnode
    struct dirnode * dn = dcache_get_dir(dir_path);
    if (dn == NULL) {
        goto out;
    }

    // 3 - Get the plain filename
    if ((result = dirnode_enc2raw(dn, fname_code, type)) == NULL) {
        goto out;
    }

    *raw_name_dest = strdup(result);
    error = 0;
out:
    if (fname_code)
        free(fname_code);
    if (dn)
        dcache_put(dn);
    return error;
}

int dirops_rename(const char * from_path, const char * to_path,
                  ucafs_entry_type type, char ** raw_name_dest)
{
    int error = AFSX_STATUS_NOOP;
    sds c_old_name = NULL, c_new_name = NULL;
    struct dirnode * dirnode1 = NULL, *dirnode2 = NULL;
    const encoded_fname_t * fname_code = NULL;

    if ((c_old_name = do_get_fname(from_path)) == NULL) {
        goto out;
    }

    if ((c_new_name = do_get_fname(to_path)) == NULL) {
        goto out;
    }

    dirnode1 = dcache_get(from_path);
    dirnode2 = dcache_get(to_path);

    if (dirnode1 == NULL || dirnode2 == NULL) {
        slog(0, SLOG_ERROR, "Could not find dirnode");
        goto out;
    }

    if (dirnode_equals(dirnode1, dirnode2)) {
        fname_code = dirnode_rename(dirnode1, c_old_name, c_new_name, type);
        if (fname_code == NULL) {
            slog(0, SLOG_ERROR, "Could not accomplish rename");
            goto out;
        }

        if (!dirnode_flush(dirnode1)) {
            slog(0, SLOG_ERROR, "Could not flush dirnode");
            goto out;
        }

        goto out1;
    }

    /* Removing from the owning dirnode */
    fname_code = dirnode_rm(dirnode1, c_old_name, type);
    if (fname_code == NULL) {
        slog(0, SLOG_ERROR, "fname '%s' does not exist", c_old_name);
        goto out;
    }

    if (!dirnode_flush(dirnode1)) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", from_path);
        goto out;
    }

    /* Adding it to the new dirnode */
    dirnode_rm(dirnode2, c_new_name, type);
    dirnode_add_alias(dirnode2, c_new_name, type, fname_code);

    if (!dirnode_flush(dirnode2)) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", to_path);
        goto out;
    }

out1:
    *raw_name_dest = encode_bin2str(fname_code);
    error = AFSX_STATUS_SUCCESS;
out:
    if (c_old_name)
        sdsfree(c_old_name);
    if (c_new_name)
        sdsfree(c_new_name);
    if (dirnode2)
        dcache_put(dirnode2);
    if (dirnode1)
        dcache_put(dirnode1);

    return error;
}

static int encode_or_remove(const char * fpath, ucafs_entry_type type,
                            char ** encoded_fname_dest, bool rm)
{
    int error = -1; // TODO
    char * fname = NULL, *c_temp = NULL;
    const encoded_fname_t * fname_code = NULL;
    sds dnode_path = NULL;

    /* 1 - Get the corresponding dirnode */
    struct dirnode * dirnode = dcache_get(fpath);
    if (dirnode == NULL) {
        goto out;
    }

    if ((fname = do_get_fname(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Could not get fname: %s", fpath);
        goto out;
    }

    /* Perform the operation */
    if ((fname_code = (rm ? dirnode_rm(dirnode, fname, type)
                          : dirnode_raw2enc(dirnode, fname, type))) == NULL) {
        slog(0, SLOG_WARN, "Could not %s: %s", (rm ? "remove" : "find"),
             fpath);
        goto out;
    }

    if (rm && !dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "Error flushing: %s", fpath);
        goto out;
    }

    c_temp = encode_bin2str(fname_code);
    /* now delete the file from the filesystem */
    if (rm && type == UCAFS_TYPE_DIR) {
        dcache_rm(fpath);
        dnode_path = uc_get_dnode_path(c_temp);
        if (unlink(dnode_path)) {
            free(c_temp);
            slog(0, SLOG_ERROR, "Could not remove: %s", dnode_path);
            goto out;
        }
    }

    *encoded_fname_dest = c_temp;
    error = 0;
out:
    if (rm && dirnode)
        dcache_put(dirnode);
    if (fname)
        sdsfree(fname);
    if (dnode_path)
        sdsfree(dnode_path);
    if (fname_code)
        free((void *)fname_code);
    return error;
}

int dirops_plain2code(const char * fpath_raw, ucafs_entry_type type,
                      char ** encoded_fname_dest)
{
    return encode_or_remove(fpath_raw, type, encoded_fname_dest, false);
}

int dirops_remove(const char * fpath_raw, ucafs_entry_type type,
                  char ** encoded_fname_dest)
{
    return encode_or_remove(fpath_raw, type, encoded_fname_dest, true);
}

