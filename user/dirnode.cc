#include <string>
#include <glog/logging.h>
#include <uuid/uuid.h>

#include "uspace.h"
#include "dirnode.h"

using namespace std;

class dnode;

DirNode::DirNode()
{
    this->proto = new dnode();
    memset(&header, 0, sizeof(file_header_t));
    header.magic = GLOBAL_MAGIC;
}

DirNode * DirNode::from_file(const char * fpath)
{
    DirNode * obj = nullptr;
    dnode * _dnode = nullptr;
    uint8_t * dnode_buf = nullptr;
    file_header_t _header;

    fstream file(fpath, ios::in | ios::binary);

    if (!file) {
        cout << "Could not read file: " << fpath;
        goto out;
    }

    file.read((char *)&_header, sizeof(file_header_t));

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
    memcpy(&obj->header, &_header, sizeof(file_header_t));

out:
    file.close();
    if (obj == nullptr) delete _dnode;
    delete[] dnode_buf;
    return obj;
}

DirNode * DirNode::from_afs_fpath(const char * fpath)
{
    // TODO for now lets assume everything is in one dnode
    return DirNode::from_file(gbl_temp_dnode_path);
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

    file->write((char *)&dn->header, sizeof(file_header_t));
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

/**
 * Adds a new file to the dirnode. Returns an encoded filename
 */
encoded_fname_t * DirNode::add_file(const char * fname)
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
    dnode_fentry * fentry = this->proto->add_file();
    fentry->set_encoded_name(encoded_name, sizeof(encoded_fname_t));
    fentry->set_raw_name(_dest_fname, slen);

    delete _dest_fname;

    return encoded_name;
}

encoded_fname_t * DirNode::rm_file(const char * realname)
{
    const char * temp;
    size_t len = strlen(realname);
    encoded_fname_t * result = nullptr;

    auto fentry_list = this->proto->mutable_file();
    auto curr_fentry = fentry_list->begin();

    while (curr_fentry != fentry_list->end()) {
        temp = curr_fentry->raw_name().data();
        // just compare
        if (memcmp(realname, temp, len) == 0) {
            result = new encoded_fname_t;
            memcpy(result, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            // delete from the list
            fentry_list->erase(curr_fentry);
            break;
        }

        curr_fentry++;
    }

    return result;
}

/**
 * Converts the encoded to the real one
 * @param encoded_name
 * @param use_malloc on if to allocate with malloc
 * @return nullptr if entry not found
 */
char * DirNode::encoded2raw(const encoded_fname_t * encoded_name,
                            bool use_malloc)
{
    char * realname = nullptr;
    for (size_t i = 0; i < this->proto->file_size(); i++) {
        auto fentry = this->proto->file(i);
        if (memcmp(encoded_name, fentry.encoded_name().data(),
                   sizeof(encoded_fname_t)) == 0) {
            size_t len = fentry.raw_name().size();
            realname = use_malloc ? (char *)calloc(1, len) : new char[len];
            memcpy(realname, fentry.raw_name().c_str(), len);
            break;
        }
    }

    return realname;
}

const encoded_fname_t * DirNode::raw2encoded(const char * realname)
{
    size_t len = strlen(realname);
    encoded_fname_t * encoded;

    for (size_t i = 0; i < this->proto->file_size(); i++) {
        auto fentry = this->proto->file(i);
        auto temp = fentry.raw_name().data();

        if (memcmp(realname, temp, len) == 0) {
            encoded = new encoded_fname_t;
            memcpy(encoded, temp, sizeof(encoded_fname_t));

            return encoded;
        }
    }

    return nullptr;
}

void DirNode::list_files()
{
    for (size_t i = 0; i < this->proto->file_size(); i++) {
        cout << this->proto->file(i).raw_name() << endl;
    }
}
