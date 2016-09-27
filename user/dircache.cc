#include <unordered_map>
#include <string>

#include "dircache.h"
#include "dirnode.h"
#include "encode.h"
#include "uspace.h"

using std::unordered_map;
using std::string;

static unordered_map <string, struct dirent *> dcache;

static struct DirNode * lookup_cache(const string& path)
{
    auto iter = dcache.find(path);
    if (iter != dcache.end()) {
        auto dnode_name = iter->second->dnode_name;
        string * dnode_path = uspace_make_dnode_fpath(dnode_name);
        // then initialize the dirnode and return it
        DirNode * dn = DirNode::from_file(dnode_path->c_str());
        delete dnode_path;
        iter->second->ref++;
        return dn;
    }

    return nullptr;
}

static dirent * add_dirnode(const string& path, const char * dnode_name)
{
    auto dentry = new dirent;
    dentry->ref = 0;
    dentry->dnode_name = strdup(dnode_name);
    dcache[path] = dentry;

    return dentry;
}

void dcache_put(struct DirNode * dirnode) 
{
    delete dirnode;
}

/**
 * Returns the path of the parent directory to the path specified
 *
 * return null if the dirnode is not found
 */
struct DirNode * dcache_get_dirnode(const char * path)
{
    struct dirent * dentry;
    DirNode * dirnode = nullptr;
    const encoded_fname_t * encoded_fname = nullptr;
    const char * c_str_fname = strdup(DEFAULT_DNODE_FNAME);
    char * pch, * nch, * c_path, * c_rel_path;
    uintptr_t ptr_val;
    string * dnode_path;
    bool found = false;

    uspace_get_relpath_c(path, &c_path);
    if (c_path == NULL) {
        return nullptr;
    }

    if ((dirnode = lookup_cache(c_path))) {
        free((void *)c_str_fname);
        return dirnode;
    }

    c_rel_path = strdup(c_path);
    ptr_val = (uintptr_t)c_path + strlen(c_path);

    dirnode = DirNode::load_default_dnode();

    nch = strtok_r(c_path, "/", &pch);
    while (nch) {
        // we ignore the last portion of the path
        if (ptr_val == (uintptr_t)pch) {
            found = true;
            break;
        }

        /* find the entry in the dirnode */
        encoded_fname = dirnode->raw2enc(nch, UCAFS_TYPE_DIR);
        if (encoded_fname == nullptr) {
            break;
        }

        /* find the dnode filename */
        if (c_str_fname) {
            free((void *)c_str_fname);
        }

        c_str_fname = encode_bin2str(encoded_fname);
        delete encoded_fname;
        if (c_str_fname == nullptr) {
            break;
        }

        dnode_path = uspace_make_dnode_fpath(c_str_fname);

        /* open the dirnode file */
        delete dirnode;
        dirnode = nullptr;
        if ((dirnode = DirNode::from_file(dnode_path->c_str())) == nullptr) {
            break;
        }

        delete dnode_path;
        dnode_path = nullptr;

        nch = strtok_r(NULL, "/", &pch);
    }

    if (dnode_path) {
        delete dnode_path;
    }

    free(c_path);
    if (found && dirnode) {
        dentry = add_dirnode(c_rel_path, c_str_fname);
        free((void *)c_str_fname);
    }
    free(c_rel_path);
    return dirnode;
}
