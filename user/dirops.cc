#include <glog/logging.h>

#include "uspace.h"
#include "crypto.h"
#include "dirnode.h"
#include "encode.h"
#include "dirops.h"

char * __get_fname(char * fpath)
{
    size_t i;
    char * result = fpath + strlen(fpath);

    while (*result != '/' && result != fpath) {
        i++;
        result--;
    }

    return strndup(result + (result != fpath), i + 1);
}

int fops_new(char * fpath, char ** encoded_name_dest)
{
    int error = -1; // TODO change this
    char * fname = __get_fname(fpath);
    DirNode * dirnode = nullptr;
    encoded_fname_t * fname_code = nullptr;

    if (fname == NULL) {
        LOG(ERROR) << "Error getting file name: " << fpath;
        goto out;
    }

    /* 1 - Get the corresponding dirnode */
    dirnode = DirNode::from_afs_fpath(fpath);
    if (dirnode == nullptr) {
        return error;
    }

    /* 2 - Get filename and add it to DirNode */
    fname_code = crypto_add_file(dirnode, fname);
    if (fname_code == nullptr) {
        LOG(ERROR) << "File: " << fpath;
        goto out;
    }

    /* 3 - Flush to disk */
    if (!dirnode->flush()) {
        LOG(ERROR) << "Flushing '" << fpath << "' failed";
        goto out;
    }

    /* 4 - Set the encoded name */
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

    /* 1 - Get the corresponding dirnode */
    DirNode * dirnode = DirNode::from_afs_fpath(dir_path);
    if (dirnode == nullptr) {
        goto out;
    }

    /* 2 - Get the binary version */
    if ((fname_code = encode_str2bin(encoded_name)) == NULL) {
        goto out;
    }

    /* 3 - Get the plain filename */
    if ((result_malloced = crypto_get_fname(dirnode, fname_code)) == NULL) {
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

int __fops_encode_or_remove(char * fpath, char ** encoded_fname_dest, bool rm)
{
    int error = -1; // TODO
    char * fname = NULL;
    encoded_fname_t * fname_code = NULL;

    /* 1 - Get the corresponding dirnode */
    DirNode * dirnode = DirNode::from_afs_fpath(fpath);
    if (dirnode == nullptr) {
        goto out;
    }

    if ((fname = __get_fname(fpath)) == NULL) {
        LOG(ERROR) << "Could not get fname: " << fpath;
        goto out;
    }

    /* Perform the operation */
    fname_code = rm ? crypto_remove_file(dirnode, fname)
                    : crypto_get_codename(dirnode, fname);
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
