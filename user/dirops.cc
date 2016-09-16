#include <glog/logging.h>

#include "uspace.h"
#include "dirnode.h"
#include "filebox.h"
#include "encode.h"
#include "dirops.h"
#include "utils.h"

int fops_new(const char * fpath, char ** encoded_name_dest)
{
    int error = -1; // TODO change this
    char * fname = dirops_get_fname(fpath), * temp;
    DirNode * dirnode = nullptr;
    FileBox * fbox = nullptr;
    encoded_fname_t * fname_code = nullptr;
    string * path1 = nullptr;

    if (fname == NULL) {
        LOG(ERROR) << "Error getting file name: " << fpath;
        goto out;
    }

    // 1 - Get the corresponding dirnode
    dirnode = DirNode::from_afs_fpath(fpath);
    if (dirnode == nullptr) {
        goto out;
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

    temp = encode_bin2str(fname_code);
    /*
    fbox = new FileBox();
    path1 = uspace_make_fbox_fpath(temp);
    if (!FileBox::write(fbox, path1->c_str())) {
        LOG(ERROR) << "Creating: " << fpath << " filebox failed";
        goto out;
    }
    */
    // 4 - Set the encoded name
    *encoded_name_dest = temp;
    error = 0;
out:
    if (fname_code)
        delete fname_code;
    if (dirnode)
        delete dirnode;
    if (fname)
        delete fname;
    if (fbox)
        delete fbox;
    if (path1)
        delete path1;

    return error;
}

int dops_new(const char * fpath, char ** encoded_name_dest)
{
    int error = -1; // TODO
    encoded_fname_t * fname_code = nullptr;
    DirNode * dirnode = nullptr, * dirnode1;
    string * path1 = nullptr;
    char * fname = dirops_get_fname(fpath), * temp;

    if (fname == nullptr) {
        LOG(ERROR) << "Error getting filename: " << fpath;
        goto out;
    }

    /* get the dirnode */
    dirnode = DirNode::from_afs_fpath(fpath);
    if (dirnode == nullptr) {
        goto out;
    }

    /* add it to the dirnode */
    fname_code = dirnode->add_dir(fname);
    if (fname_code == nullptr) {
        LOG(ERROR) << "Could not add: " << fpath;
        goto out;
    }

    if (!dirnode->flush()) {
        LOG(ERROR) << "Flushing: " << fpath << " failed";
        goto out;
    }

    temp = encode_bin2str(fname_code);

    /* create the new dirnode */
    dirnode1 = new DirNode();
    path1 = uspace_make_dnode_fpath(temp);
    if (!DirNode::write(dirnode1, path1->c_str())) {
        LOG(ERROR) << "Creating: " << fpath << " dirnode failed";
        goto out;
    }

    *encoded_name_dest = temp;
    error = 0;
out:
    if (fname_code)
        delete fname_code;
    if (dirnode)
        delete dirnode;
    if (dirnode1)
        delete dirnode1;
    if (fname)
        delete fname;
    if (path1)
        delete path1;

    return error;
}

int fops_code2plain(char * encoded_name, char * dir_path, char ** raw_name_dest)
{
    int error = -1; // TODO
    encoded_fname_t * fname_code = NULL;
    char * result_malloced;

    // 1 - Get the binary version
    if ((fname_code = encode_str2bin(encoded_name)) == NULL) {
        return -1;
    }

    // 2 - Get the corresponding dirnode
    DirNode * dirnode = DirNode::from_afs_fpath(dir_path, false);
    if (dirnode == nullptr) {
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
    return 0;
}

#if 0
int fops_rename(char * old_plain_path, char * new_plain_path, int file_or_dir,
                char ** raw_name_dest)
{
    // TODO check if both files are in the same folder
    int error = -1;
    char * old_fname, *new_fname;
    DirNode * dirnode1 = nullptr, dirnode2 = nullptr;
    const encoded_fname_t * fname_code1 = nullptr, * fname_code1 = nullptr;

    dirnode1 = DirNode::from_afs_fpath(old_plain_path);
    if (dirnode1 == nullptr) {
        goto out;
    }

    dirnode2 = DirNode::from_afs_fpath(new_plain_path);
    if (dirnode2 == nullptr) {
        goto out;
    }

    if ((old_fname = dirops_get_fname(old_plain_path)) == NULL
        || (new_fname = dirops_get_fname(new_plain_path)) == NULL) {
        goto out;
    }

    fname_code1 = dirnode1->rm_file(old_fname);
    if (fname_code1) {
        LOG(ERROR) << "deleting " << old_fname << "from dirnode";
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
    if (dirnode1)
        delete dirnode1;
    if (dirnode2)
        delete dirnode2;
    if (old_fname)
        free(old_fname);
    if (new_fname)
        free(new_fname);
    if (fname_code)
        delete fname_code;
    return error;
}
#endif
int __fops_encode_or_remove(const char * fpath, char ** encoded_fname_dest, bool rm)
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

int fops_remove(const char * fpath_raw, char ** encoded_fname_dest)
{
    return __fops_encode_or_remove(fpath_raw, encoded_fname_dest, true);
}

int dops_remove(const char * dpath_raw, char ** encoded_dname_dest)
{
    int error = AFSX_STATUS_ERROR;
    char * c_dname = NULL, * c_temp = NULL;
    string * dnode_path = nullptr;
    const encoded_fname_t * dname_code = NULL;

    /* 1 - Get the corresponding dirnode */
    DirNode * dirnode = DirNode::from_afs_fpath(dpath_raw);
    if (dirnode == nullptr) {
        goto out;
    }

    if ((c_dname = dirops_get_fname(dpath_raw)) == nullptr) {
        LOG(ERROR) << "Could not get fname: " << dpath_raw;
        goto out;
    }

    /* Perform the operation */
    if ((dname_code = dirnode->rm_dir(c_dname)) == nullptr) {
        goto out;
    }

    /* writeout the dirnode */
    if (!dirnode->flush()) {
        LOG(ERROR) << "Error flushing: " << dirnode->get_fpath();
        goto out;
    }

    /* now delete the file from the filesystem */
    c_temp = encode_bin2str(dname_code);
    dnode_path = uspace_make_dnode_fpath(c_temp);
    if (unlink(dnode_path->c_str())) {
        LOG(ERROR) << "Could not remove: " << dnode_path->c_str();
    }

    *encoded_dname_dest = c_temp;
    error = 0;
out:
    if (dirnode)
        delete dirnode;
    if (c_dname)
        free(c_dname);
    if (dname_code)
        delete dname_code;
    if (dnode_path)
        delete dnode_path;
    if (error && c_temp)
        free(c_temp);
    return error;
}

/**
 * Looks up a plain path and derives the destination encoded filename
 *
 */
int dops_lookup_path(char * fpath_raw, char ** encoded_dnode_dest)
{
    int error =  -1;


    return error;
}
