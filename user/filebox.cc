#include <iostream>
#include <fstream>
#include "filebox.h"
#include "uspace.h"

using namespace std;

FileBox::FileBox()
{
    memset(&this->header, 0, sizeof(fbox_header_t));
    this->proto = new class ::fbox;

    // every filebox has a default segmentt
    this->create_segment();
}

FileBox * FileBox::from_afs_file(const char * fname) {
    return new FileBox();
}

FileBox * FileBox::from_file(const char * fname)
{
    FileBox * filebox = nullptr;
    fbox * _fbox = nullptr;
    fbox_header_t _header;
    uint8_t * buffer;
    string * fpath = uspace_make_dnode_fpath(fname);

    fstream file(fpath->c_str(), ios::in | ios::binary);
    if (!file) {
        cout << "Could not read file: " << fpath << endl;
        goto out;
    }

    file.read((char *)&_header, sizeof(fbox_header_t));

    _fbox = new class ::fbox;
    if (_header.plen) {
        buffer = new uint8_t[_header.plen];

        if (!_fbox->ParseFromArray(buffer, _header.plen)) {
            cout << "! Parsing protocol buffer failed: " << fpath->c_str()
                 << endl;
            goto out;
        }
    }

    filebox = new FileBox();
    filebox->proto = _fbox;
    memcpy(&filebox->header, &_header, sizeof(fbox_header_t));
out:
    if (filebox == nullptr) {
        delete _fbox;
    }

    if (buffer) {
        delete[] buffer;
    }

    file.close();
    return filebox;
}

encoded_fname_t * FileBox::create_segment()
{
    encoded_fname_t * rv = new encoded_fname_t;
    fbox_segment * seg = this->proto->add_seg();
    crypto_context_t file_crypto;

    memset(&file_crypto, 0, sizeof(crypto_context_t));
    // TODO call enclave here to setup
    seg->set_crypto((char *)&file_crypto, sizeof(crypto_context_t));

    this->header.seg_count++;
    seg->set_num(this->header.seg_count);

    uuid_generate_time_safe(rv->bin);
    seg->set_name((char *)rv, sizeof(encoded_fname_t));

    seg->set_size(0);

    return rv;
}

crypto_context_t * FileBox::segment_crypto(uint32_t seg_id)
{
    crypto_context_t * fcrypto;
    if (this->proto->seg_size()) {
        fcrypto = new crypto_context_t;
        memcpy(fcrypto, this->proto->seg(seg_id).crypto().data(),
               sizeof(crypto_context_t));
        return fcrypto;
    }
    return nullptr;
}

encoded_fname_t * FileBox::segment_name(uint32_t seg_id)
{
    encoded_fname_t * fname;
    if (this->proto->seg_size()) {
        fname = new encoded_fname_t;
        memcpy(fname, this->proto->seg(seg_id).name().data(),
               sizeof(encoded_fname_t));
        return fname;
    }
    return nullptr;
}

bool FileBox::write(FileBox * fb, fstream * file)
{
    bool error = false;
    size_t len = CRYPTO_CEIL_TO_BLKSIZE(fb->proto->ByteSize());
    uint8_t * buffer = new uint8_t[len];

    if (!fb->proto->SerializeToArray(buffer, len)) {
        cout << "! filebox Serialization failed" << endl;
        goto out;
    }

    fb->header.plen = fb->proto->GetCachedSize();
    // TODO call enclave here

    file->write((char *)&fb->header.plen, sizeof(fbox_header_t));
    file->write((char *)buffer, fb->header.plen);

    error = true;
out:
    delete[] buffer;
    return error;
}

bool FileBox::write(FileBox * fb, const char * path)
{
    fstream file(path, ios::trunc | ios::out | ios::binary);
    bool ret = file ? FileBox::write(fb, &file) : false;

    file.close();
    return ret;
}
