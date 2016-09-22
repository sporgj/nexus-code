#include <string>
#include <unistd.h>

#include "uspace.h"
#include "dirnode.h"
#include "filebox.h"
#include "encode.h"
#include "dircache.h"
#include "dirops.h"
#include "utils.h"
#include "slog.h"

int dirops_new(const char * fpath, ucafs_entry_type type,
               char ** encoded_name_dest)
{
    int error = -1; // TODO change this
    char * fname = dirops_get_fname(fpath), *temp;
    DirNode * dirnode = nullptr, *dirnode1 = nullptr;
    FileBox * fbox = nullptr;
    const encoded_fname_t * fname_code = nullptr;
    string * path1 = nullptr;
    struct dirent * dirent;

    if (fname == NULL) {
        slog(0, SLOG_ERROR, "Error getting file name: %s", fpath);
        goto out;
    }

    /* lets get the directory entry */
    dirnode = dcache_lookup(std::string(fpath));
    if (dirnode == nullptr) {
        slog(0, SLOG_ERROR, "Error loading dirnode: %s", fpath);
        goto out;
    }

    /* Get filename and add it to DirNode */
    fname_code = dirnode->add(fname, type);
    if (fname_code == nullptr) {
        slog(0, SLOG_ERROR, "Add file operation failed: %s", fpath);
        goto out;
    }

    // 3 - Flush to disk
    if (!dirnode->flush()) {
        slog(0, SLOG_ERROR, "Flushing '%s' failed", fpath);
        goto out;
    }

    temp = encode_bin2str(fname_code);

    if (type == UCAFS_TYPE_DIR) {
        dirnode1 = new DirNode();
        path1 = uspace_make_dnode_fpath(temp);
        if (!DirNode::write(dirnode1, path1->c_str())) {
            slog(0, SLOG_ERROR, "Creating: '%s' dirnode failed", fpath);
            goto out;
        }
    } else if (type == UCAFS_TYPE_FILE) {
    }

    /* Set the encoded name */
    *encoded_name_dest = temp;
    error = 0;
out:
    if (fname_code)
        delete fname_code;
    if (dirnode)
        dcache_put(dirnode);
    if (dirnode1)
        dcache_put(dirnode1);
    if (fname)
        delete fname;
    if (fbox)
        delete fbox;
    if (path1)
        delete path1;

    return error;
}

int dirops_code2plain(char * encoded_name, char * dir_path,
                      ucafs_entry_type type, char ** raw_name_dest)
{
    int error = -1; // TODO
    encoded_fname_t * fname_code = NULL;
    const char * result;
    std::string path_string(dir_path);

    /* 1 - Get the binary version */
    if ((fname_code = encode_str2bin(encoded_name)) == NULL) {
        return -1;
    }

    // 2 - Get the corresponding dirnode
    path_string += "/";
    DirNode * dirnode = dcache_lookup(path_string);
    if (dirnode == nullptr) {
        goto out;
    }

    // 3 - Get the plain filename
    if ((result = dirnode->lookup(fname_code, type)) == NULL) {
        goto out;
    }

    *raw_name_dest = strdup(result);
    error = 0;
out:
    if (fname_code)
        delete fname_code;
    if (dirnode)
        dcache_put(dirnode);
    return error;
}

int dirops_rename(const char * from_path, const char * to_path,
                  ucafs_entry_type type, char ** raw_name_dest)
{
    int error = AFSX_STATUS_NOOP;
    char * c_old_name = NULL, *c_new_name = NULL;
    DirNode * dirnode1 = nullptr, *dirnode2 = nullptr;
    const encoded_fname_t * fname_code = nullptr;

    if ((c_old_name = dirops_get_fname(from_path)) == nullptr) {
        goto out;
    }

    if ((c_new_name = dirops_get_fname(to_path)) == nullptr) {
        goto out;
    }

    dirnode1 = dcache_lookup(std::string(from_path));
    dirnode2 = dcache_lookup(std::string(to_path));

    if (dirnode1 == nullptr || dirnode2 == nullptr) {
        slog(0, SLOG_ERROR, "Could not find dirnode");
        goto out;
    }

    if (dirnode1->operator==(*dirnode2)) {
        dirnode1->rename(c_old_name, c_new_name, type);

        dirnode1->flush();
        goto out;
    }

    /* Removing from the owning dirnode */
    fname_code = dirnode1->rm(c_old_name, type);
    if (fname_code == nullptr) {
        slog(0, SLOG_ERROR, "fname '%s' does not exist", c_old_name);
        goto out;
    }

    if (!dirnode1->flush()) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", from_path);
        goto out;
    }

    /* Adding it to the new dirnode */
    dirnode2->rm(c_new_name, type);
    dirnode2->rm(c_old_name, type);

    if (!dirnode2->flush()) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", to_path);
        goto out;
    }

    *raw_name_dest = encode_bin2str(fname_code);
    error = AFSX_STATUS_SUCCESS;
out:
    if (c_old_name)
        free(c_old_name);
    if (c_new_name)
        free(c_new_name);
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
    string * dnode_path = nullptr;

    /* 1 - Get the corresponding dirnode */
    DirNode * dirnode = dcache_lookup(fpath);
    if (dirnode == nullptr) {
        goto out;
    }

    if ((fname = dirops_get_fname(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Could not get fname: %s", fpath);
        goto out;
    }

    /* Perform the operation */
    if ((fname_code = dirnode->rm(fname, type)) == nullptr) {
        slog(0, SLOG_ERROR, "Could not remove: %s", fpath);
        goto out;
    }

    if (rm && !dirnode->flush()) {
        slog(0, SLOG_ERROR, "Error flushing: %s", fpath);
        goto out;
    }

    /* now delete the file from the filesystem */
    if (type == UCAFS_TYPE_DIR) {
        c_temp = encode_bin2str(fname_code);
        dnode_path = uspace_make_dnode_fpath(c_temp);
        if (unlink(dnode_path->c_str())) {
            slog(0, SLOG_ERROR, "Could not remove: %s", dnode_path->c_str());
            goto out;
        }
    }

    *encoded_fname_dest = encode_bin2str(fname_code);
    error = 0;
out:
    if (rm && dirnode)
        dcache_put(dirnode);
    if (fname)
        delete fname;
    if (fname_code)
        delete fname_code;
    if (dnode_path)
        delete dnode_path;
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
