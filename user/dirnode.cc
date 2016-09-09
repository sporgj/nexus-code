#include <string>
#include <glog/logging.h>
#include <uuid/uuid.h>

#include "uspace.h"
#include "dirnode.h"
#include "encode.h"

using namespace std;

class dnode;

string DirNode::DNODE_HOME_DIR = "";

DirNode::DirNode()
{
    this->proto = new dnode();
    memset(&header, 0, sizeof(dnode_header_t));
    header.magic = GLOBAL_MAGIC;
}

inline DirNode * DirNode::load_default_dnode()
{
    string * path = uspace_get_dnode_fpath();
    DirNode * dnode = DirNode::from_file(path->c_str());
    delete path;

    return dnode;
}

/**
 * Returns the DirNode object containing the following object
 * @param path is the path to the object
 * @param home_folder is the folder in which the cell resides
 * @return NULL if the path is invalid
 */
DirNode * DirNode::lookup_path(const char * path, bool omit_last)
{
    char * p_path = strdup((char *)path), *pch, *nch;
    uintptr_t ptr_val = (uintptr_t)p_path + strlen(path);
    DirNode * dirnode = DirNode::load_default_dnode();
    const encoded_fname_t * encoded_fname = nullptr;
    const char * encoded_str = nullptr;
    string * dnode_path = nullptr;

    nch = strtok_r(p_path, "/", &pch);
    while (nch) {
        if (omit_last && ptr_val == (uintptr_t)pch) {
            break;
        }

        // let's lookup into the value passed
        if ((encoded_fname = dirnode->find_dir_by_raw_name(nch)) == NULL) {
            dirnode = nullptr;
            break;
        }

        encoded_str = encode_bin2str(encoded_fname);
        delete encoded_fname;

        dnode_path = uspace_make_dnode_fpath(encoded_str);
        free((void *) encoded_str);

        if ((dirnode = DirNode::from_file(dnode_path->c_str())) == nullptr) {
            break;
        }
        delete dnode_path;
        dnode_path = nullptr;

        nch = strtok_r(NULL, "/", &pch);
    }

    if (dnode_path)
        delete dnode_path;

    free(p_path);
    return dirnode;
}

DirNode * DirNode::from_file(const char * fpath)
{
    DirNode * obj = nullptr;
    dnode * _dnode = nullptr;
    uint8_t * dnode_buf = nullptr;
    dnode_header_t _header;

    fstream file(fpath, ios::in | ios::binary);

    if (!file) {
        cout << "Could not read file: " << fpath << endl;
        goto out;
    }

    file.read((char *)&_header, sizeof(dnode_header_t));

    if (_header.magic != GLOBAL_MAGIC) {
        cout << "\n ! Error with file format" << endl;
        goto out;
    }

    _dnode = new class ::dnode;

    if (_header.len) {
        dnode_buf = new uint8_t[_header.len];
        file.read((char *)dnode_buf, _header.len);

        // TODO call the enclave

        if (!_dnode->ParseFromArray(dnode_buf, _header.len)) {
            cout << "\n ! Parsing protocol buffer failed: " << fpath << endl;
            goto out;
        }
    }

    obj = new DirNode();
    obj->proto = _dnode;
    obj->dnode_fpath = new string(fpath);
    memcpy(&obj->header, &_header, sizeof(dnode_header_t));

out:
    file.close();
    if (obj == nullptr)
        delete _dnode;
    delete[] dnode_buf;
    return obj;
}

DirNode * DirNode::from_afs_fpath(const char * fpath, bool omit_last)
{
    // TODO for now lets assume everything is in one dnode
    char * relpath;
    uspace_get_relpath(fpath, &relpath);
    return DirNode::lookup_path(relpath, omit_last);
}

bool DirNode::write(DirNode * dn, fstream * file)
{
    bool ret = false;

    uint8_t * dnode_buf = nullptr;
    size_t len = CRYPTO_CEIL_TO_BLKSIZE(dn->proto->ByteSize());
    dnode_buf = new uint8_t[len];

    if (!dn->proto->SerializeToArray(dnode_buf, len)) {
        cout << "\n ! Serialization failed" << endl;
        goto out;
    }

    dn->header.len = dn->proto->GetCachedSize();

    // TODO call enclave

    file->write((char *)&dn->header, sizeof(dnode_header_t));
    file->write((char *)dnode_buf, dn->header.len);
    ret = true;
out:
    delete[] dnode_buf;
    return ret;
}

bool DirNode::write(DirNode * dn, const char * fpath)
{
    // no partial writes supported
    fstream file(fpath, ios::trunc | ios::out | ios::binary);
    bool ret = file ? DirNode::write(dn, &file) : false;

    file.close();
    return ret;
}

encoded_fname_t * DirNode::__add_entry(const char * fname, bool is_file)
{
    encoded_fname_t * encoded_name;
    raw_fname_t * _dest_fname;
    size_t slen = strlen(fname) + 1;

    encoded_name = new encoded_fname_t;
    _dest_fname = static_cast<raw_fname_t *>(operator new(slen));
    memset(_dest_fname, 0, slen);

    uuid_generate_time_safe(encoded_name->bin);

    memcpy(_dest_fname->raw, fname, strlen(fname));

    // add the mapping to our dnode
    dnode_fentry * fentry = is_file ? this->proto->add_file()
                                    : this->proto->add_dir();
    fentry->set_encoded_name(encoded_name, sizeof(encoded_fname_t));
    fentry->set_raw_name(_dest_fname, slen);

    header.count++;

    delete _dest_fname;

    return encoded_name;
}

/**
 * Adds a new file to the dirnode. Returns an encoded filename
 */
encoded_fname_t * DirNode::add_file(const char * fname)
{
    return this->__add_entry(fname, true);
}

encoded_fname_t * DirNode::add_dir(const char * fname)
{
    return this->__add_entry(fname, false);
}

encoded_fname_t * DirNode::__rm_entry(const char * realname, bool is_file)
{
    encoded_fname_t * result = nullptr;

    string name_str(realname);
    auto fentry_list = is_file ? this->proto->mutable_file()
                               : this->proto->mutable_dir();
    auto curr_fentry = fentry_list->begin();

    while (curr_fentry != fentry_list->end()) {
        if (!name_str.compare(curr_fentry->raw_name().data())) {
            result = new encoded_fname_t;
            memcpy(result, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            // delete from the list
            fentry_list->erase(curr_fentry);
            header.count--;
            break;
        }

        curr_fentry++;
    }

    return result;
}

encoded_fname_t * DirNode::rm_file(const char * realname)
{
    return this->__rm_entry(realname, true);
}

encoded_fname_t * DirNode::rm_dir(const char * realname)
{
    return this->__rm_entry(realname, false);
}

encoded_fname_t * DirNode::rename_file(const char * oldname,
                                       const char * newname)
{
#if 0
    encoded_fname_t * new_encoded_name;
    raw_fname_t * dest_fname;
    if (!rm_file(oldname)) {
        return nullptr;
    }

    size_t slen = strlen(newname) + 1;

    dest_fname = static_cast<raw_fname_t *>(operator new(slen));
    memset(dest_fname, 0, slen);

    memcpy(dest_fname->raw, newname, strlen(newname));

    new_encoded_name = new encoded_fname_t;
    uuid_generate_time_safe(new_encoded_name->bin);

    dnode_fentry * fentry = this->proto->add_file();
    fentry->set_encoded_name(new_encoded_name, sizeof(encoded_fname_t));
    fentry->set_raw_name(dest_fname, slen);

    delete dest_fname;
    return new_encoded_name;
#else
    encoded_fname_t * encoded_name;
    auto fentry_list = this->proto->mutable_file();
    auto curr_fentry = fentry_list->begin();
    string name_str(oldname);

    while (curr_fentry != fentry_list->end()) {
        if (!name_str.compare(curr_fentry->raw_name().data())) {
            encoded_name = new encoded_fname_t;
            uuid_generate_time_safe(encoded_name->bin);

            curr_fentry->set_raw_name(newname);
            curr_fentry->set_encoded_name(encoded_name->bin,
                                          sizeof(encoded_fname_t));

            return encoded_name;
        }

        curr_fentry++;
    }

    return nullptr;
#endif
}

/**
 * Converts the encoded to the real one
 * @param encoded_name
 * @param use_malloc on if to allocate with malloc
 * @return nullptr if entry not found
 */
char * DirNode::__enc2raw(const encoded_fname_t * encoded_name, bool use_malloc,
                          bool is_file)
{
    char * realname = nullptr;

    auto fentry_list = is_file ? this->proto->file() : this->proto->dir();
    auto curr_fentry = fentry_list.begin();
    while (curr_fentry != fentry_list.end()) {
        if (memcmp(encoded_name, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t)) == 0) {
            size_t len = curr_fentry->raw_name().size();
            realname = use_malloc ? (char *)calloc(1, len + 1)
                                  : new char[len + 1];
            memcpy(realname, curr_fentry->raw_name().c_str(), len);
            break;
        }

        curr_fentry++;
    }

    return realname;
}

const encoded_fname_t * DirNode::__raw2enc(const char * realname, bool is_file)
{
    size_t len = strlen(realname);
    encoded_fname_t * encoded;

    auto fentry_list = is_file ? this->proto->file() : this->proto->dir();
    auto curr_fentry = fentry_list.begin();
    while (curr_fentry != fentry_list.end()) {
        if (strncmp(realname, curr_fentry->raw_name().data(), len) == 0) {
            encoded = new encoded_fname_t;
            memcpy(encoded, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            return encoded;
        }
        curr_fentry++;
    }

    return nullptr;
}

char * DirNode::encoded2raw(const encoded_fname_t * encoded_name,
                            bool use_malloc)
{
    char * value = this->__enc2raw(encoded_name, use_malloc, true);
    return value ? value : this->__enc2raw(encoded_name, use_malloc, false);
}

const encoded_fname_t * DirNode::raw2encoded(const char * realname)
{
    const encoded_fname_t * value = this->__raw2enc(realname, true);
    return value ? value : this->__raw2enc(realname, false);
}

void DirNode::list_files()
{
    for (size_t i = 0; i < this->proto->file_size(); i++) {
        cout << this->proto->file(i).raw_name() << endl;
    }

    for (size_t i = 0; i < this->proto->dir_size(); i++) {
        cout << this->proto->dir(i).raw_name() << "/" << endl;
    }
}
