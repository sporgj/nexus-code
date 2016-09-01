#include <glog/logging.h>

#include "uspace.h"
#include "dirnode.h"
#include "encode.h"
#include "dirops.h"
#include "utils.h"

int fops_new(char * fpath, char ** encoded_name_dest)
{
    int error = -1; // TODO change this
    char * fname = dirops_get_fname(fpath);
    DirNode * dirnode = nullptr;
    encoded_fname_t * fname_code = nullptr;

    if (fname == NULL) {
        LOG(ERROR) << "Error getting file name: " << fpath;
        goto out;
    }

    // 1 - Get the corresponding dirnode
    dirnode = DirNode::from_afs_fpath(fpath);
    if (dirnode == nullptr) {
        return error;
    }

    // 2 - Get filename and add it to DirNode
    fname_code = dirnode->add_file(fname);
    if (fname_code == nullptr) {
        LOG(ERROR) << "File: " << fpath;
        goto out;
    }

    // 3 - Flush to disk
    if (!dirnode->flush()) {
        LOG(ERROR) << "Flushing '" << fpath << "' failed";
        goto out;
    }

    // 4 - Set the encoded name
    *encoded_name_dest = encode_bin2str(fname_code);
    error = 0;
out:
    if (fname_code)
        delete fname_code;
    if (dirnode)
        delete dirnode;
    if (fname)
        delete fname;

    return error;
}

int fops_code2plain(char * encoded_name, char * dir_path, char ** raw_name_dest)
{
    int error = -1; // TODO
    encoded_fname_t * fname_code = NULL;
    char * result_malloced;

    // 1 - Get the corresponding dirnode
    DirNode * dirnode = DirNode::from_afs_fpath(dir_path);
    if (dirnode == nullptr) {
        goto out;
    }

    // 2 - Get the binary version
    if ((fname_code = encode_str2bin(encoded_name)) == NULL) {
        goto out;
    }

    // 3 - Get the plain filename
    if ((result_malloced = dirnode->encoded2raw(fname_code, true)) == NULL) {
        goto out;
    }

    *raw_name_dest = result_malloced;
    error = 0;
out:
    if (fname_code)
        delete fname_code;
    if (dirnode)
        delete dirnode;
    return error;
}

int fops_rename(char * old_plain_path, char * new_plain_path,
                char ** raw_name_dest)
{
    // TODO check if both files are in the same folder
    int error = -1;
    char * old_fname, *new_fname;
    const encoded_fname_t * fname_code = nullptr;

    DirNode * dirnode = DirNode::from_afs_fpath(old_plain_path);
    if (dirnode == nullptr) {
        goto out;
    }

    if ((old_fname = dirops_get_fname(old_plain_path)) == NULL
        || (new_fname = dirops_get_fname(new_plain_path)) == NULL) {
        goto out;
    }

    fname_code = dirnode->rename_file(old_fname, new_fname);
    if (!fname_code) {
        goto out;
    }

    if (!dirnode->flush()) {
        LOG(ERROR) << "rename, error flushing: " << old_plain_path << " -> "
                   << new_plain_path;
        goto out;
    }

    *raw_name_dest = encode_bin2str(fname_code);
    error = 0;
out:
    if (old_fname)
        free(old_fname);
    if (new_fname)
        free(new_fname);
    if (fname_code)
        delete fname_code;
    return error;
}

int __fops_encode_or_remove(char * fpath, char ** encoded_fname_dest, bool rm)
{
    int error = -1; // TODO
    char * fname = NULL;
    const encoded_fname_t * fname_code = NULL;

    /* 1 - Get the corresponding dirnode */
    DirNode * dirnode = DirNode::from_afs_fpath(fpath);
    if (dirnode == nullptr) {
        goto out;
    }

    if ((fname = dirops_get_fname(fpath)) == NULL) {
        LOG(ERROR) << "Could not get fname: " << fpath;
        goto out;
    }

    /* Perform the operation */
    fname_code = rm ? dirnode->rm_file(fname) : dirnode->raw2encoded(fname);
    if (!fname_code) {
        goto out;
    }

    if (rm && !dirnode->flush()) {
        LOG(ERROR) << "Error flushing: " << dirnode->get_fpath();
        goto out;
    }

    *encoded_fname_dest = encode_bin2str(fname_code);
    error = 0;
out:
    if (dirnode)
        delete dirnode;
    if (fname)
        delete fname;
    if (fname_code)
        delete fname_code;
    return error;
}

int fops_plain2code(char * fpath_raw, char ** encoded_fname_dest)
{
    return __fops_encode_or_remove(fpath_raw, encoded_fname_dest, false);
}

int fops_remove(char * fpath_raw, char ** encoded_fname_dest)
{
    return __fops_encode_or_remove(fpath_raw, encoded_fname_dest, true);
}
