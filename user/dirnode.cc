#include <string>
#include <glog/logging.h>

#include "uspace.h"
#include "dirnode.h"

using namespace std;

class dnode;

DirNode::DirNode()
{
    this->proto = new dnode();

    proto->set_count(0);
    proto->clear_ekey();
    proto->clear_mac();
}

DirNode * DirNode::from_file(const char * fpath, bool readonly)
{
    DirNode * object = nullptr;
    dnode * _dnode = new class ::dnode();
    fstream input(fpath,
                  ios::binary | (readonly ? ios::in : ios::in | ios::out));

    if (!_dnode->ParseFromIstream(&input)) {
        LOG(ERROR) << "Could not parse from '" << fpath << "'" << endl;
        delete _dnode;
        goto out;
    }

    input.close();

    object = new DirNode(_dnode);

out:
    return object;
}

DirNode * DirNode::from_afs_fpath(const char * fpath)
{
    // TODO for now lets assume everything is in one dnode
    DirNode * object = nullptr;
    dnode * _dnode = new class ::dnode();
    fstream input(gbl_temp_dnode_path, ios::binary | ios::in);

    if (!_dnode->ParseFromIstream(&input)) {
        LOG(ERROR) << "Could not parse: " << gbl_temp_dnode_path;
        goto out;
    }

    input.close();

    object = new DirNode(_dnode);
    object->dnode_fpath = new string(gbl_temp_dnode_path);
out:
    return object;
}

bool DirNode::add(encoded_fname_t * encoded_fname, raw_fname_t * raw_fname,
                  crypto_iv_t * iv)
{
    class ::dnode_fentry * fentry = proto->add_file();
    fentry->set_encoded_name(encoded_fname, sizeof(encoded_fname_t));
    fentry->set_raw_name(raw_fname, raw_fname->len + sizeof(raw_fname->len));
    fentry->set_iv(iv, sizeof(crypto_iv_t));

    uint32_t count = proto->count();
    proto->set_count(++count);

    return true;
}

bool DirNode::write(DirNode * fb, fstream * fd)
{
    return fb->proto->SerializeToOstream(fd);
}

bool DirNode::write(DirNode * fb, const char * fpath)
{
    fstream input(fpath, ios::in | ios::out | ios::trunc);
    bool rv = DirNode::write(fb, &input);
    input.close();

    return rv;
}

void DirNode::list_files() {
}
