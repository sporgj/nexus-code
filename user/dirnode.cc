#include <string>
#include <glog/logging.h>
#include <uuid/uuid.h>

#include "uspace.h"
#include "dirnode.h"
#include "encode.h"

using namespace std;
using namespace ::google::protobuf;

class dnode;

DirNode::DirNode()
{
    this->proto = new dnode();
    memset(&header, 0, sizeof(dnode_header_t));
    header.magic = GLOBAL_MAGIC;
    uuid_generate_time_safe(header.uuid);
}

DirNode * DirNode::load_default_dnode()
{
    string * path = uspace_main_dnode_fpath();
    DirNode * dnode = DirNode::from_file(path->c_str());
    delete path;

    return dnode;
}

bool DirNode::operator==(const DirNode & d)
{
    return memcmp(&this->header.uuid, &d.header.uuid, sizeof(uuid_t)) == 0;
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

const encoded_fname_t * DirNode::add(const char * name, ucafs_entry_type type,
                                     const encoded_fname_t * p_encoded_name)
{
    encoded_fname_t * encoded_name;
    dnode_fentry * fentry;

    if (type == UCAFS_TYPE_UNKNOWN) {
        return nullptr;
    }

    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry = this->proto->add_file();
        break;
    case UCAFS_TYPE_DIR:
        fentry = this->proto->add_dir();
        break;
    default:
        return nullptr;
    }

    encoded_name = new encoded_fname_t;
    if (p_encoded_name) {
        memcpy(encoded_name, p_encoded_name, sizeof(encoded_fname_t));
    } else {
        uuid_generate_time_safe(encoded_name->bin);
    }

    fentry->set_encoded_name(encoded_name, sizeof(encoded_fname_t));
    fentry->set_raw_name(name);

    this->header.count++;

    return encoded_name;
}

const encoded_fname_t * DirNode::rm(const char * realname,
                                    ucafs_entry_type type)
{
    encoded_fname_t * result = nullptr;
    string name_str(realname);
    bool iterate = (type == UCAFS_TYPE_UNKNOWN);
    RepeatedPtrField<dnode_fentry> * fentry_list;
retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = this->proto->mutable_file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = this->proto->mutable_dir();
        break;
    default:
        return nullptr;
    }

    auto curr_fentry = fentry_list->begin();

    while (curr_fentry != fentry_list->end()) {
        if (!name_str.compare(curr_fentry->raw_name().data())) {
            result = new encoded_fname_t;
            memcpy(result, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            // delete from the list
            fentry_list->erase(curr_fentry);
            header.count--;
            return result;
        }

        curr_fentry++;
    }

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return nullptr;
}

const char * DirNode::lookup(const encoded_fname_t * encoded_name,
                             ucafs_entry_type type)
{
    bool iterate = (type == UCAFS_TYPE_UNKNOWN);
    const RepeatedPtrField<dnode_fentry> * fentry_list;

retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = &this->proto->file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = &this->proto->dir();
        break;
    default:
        return nullptr;
    }

    auto curr_fentry = fentry_list->begin();
    while (curr_fentry != fentry_list->end()) {
        if (memcmp(encoded_name, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t)) == 0) {
            return curr_fentry->raw_name().c_str();
        }

        curr_fentry++;
    }

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return nullptr;
}

const encoded_fname_t * DirNode::find(const char * realname,
                                      ucafs_entry_type type)
{
    size_t len = strlen(realname);
    encoded_fname_t * encoded;
    string name_str(realname);
    bool iterate = (type == UCAFS_TYPE_UNKNOWN);
    const RepeatedPtrField<dnode_fentry> * fentry_list;

retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = &this->proto->file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = &this->proto->dir();
        break;
    default:
        return nullptr;
    }

    auto curr_fentry = fentry_list->begin();
    while (curr_fentry != fentry_list->end()) {
        if (!name_str.compare(curr_fentry->raw_name().data())) {
            encoded = new encoded_fname_t;
            memcpy(encoded, curr_fentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            return encoded;
        }
        curr_fentry++;
    }

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return nullptr;
}

const encoded_fname_t * DirNode::rename(const char * oldname,
                                        const char * newname,
                                        ucafs_entry_type type)
{
    encoded_fname_t * encoded_name;
    string name_str(oldname);
    RepeatedPtrField<dnode_fentry> * fentry_list;
    bool iterate = (type == UCAFS_TYPE_UNKNOWN);

retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = this->proto->mutable_file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = this->proto->mutable_dir();
        break;
    default:
        return nullptr;
    }

    auto curr_fentry = fentry_list->begin();
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

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return nullptr;
}

#ifdef UCAFS_DEBUG
void DirNode::list_files()
{
    for (size_t i = 0; i < this->proto->file_size(); i++) {
        cout << this->proto->file(i).raw_name() << endl;
    }

    for (size_t i = 0; i < this->proto->dir_size(); i++) {
        cout << this->proto->dir(i).raw_name() << "/" << endl;
    }
}
#endif
