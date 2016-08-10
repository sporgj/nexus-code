#pragma once
#include <string>
#include <iostream>
#include <fstream>

extern "C" {
#include "types.h"
}
#include "dnode.pb.h"

using std::string;
using std::fstream;

class dnode;

class DirNode {
private:
    dnode * proto;
    string * dnode_fpath = nullptr;

    /**
     * Private constructor static constructor
     * @param fb is the dnode object
     * @param fd is the file stream object
     */
    DirNode(dnode * fb) { this->proto = fb; };

public:
    DirNode();
    inline void set_ekey(crypto_ekey_t * ekey)
    {
        proto->set_ekey(ekey, sizeof(crypto_ekey_t));
    }

    inline void set_mac(crypto_mac_t * mac)
    {
        proto->set_mac(mac, sizeof(crypto_mac_t));
    }

    inline const char * get_fpath()
    {
        return dnode_fpath ? dnode_fpath->c_str() : NULL;
    }

    inline void dump() { std::cout << proto->DebugString() << std::endl; }

    static DirNode * from_file(const char * fpath, bool readonly);
    static DirNode * from_afs_fpath(const char * fpath);
    static bool write(DirNode * fb, fstream * fd);
    static bool write(DirNode * fb, const char * fpath);

    bool add(encoded_fname_t * encoded_fname, raw_fname_t * fname,
             crypto_iv_t * iv);
    void list_files();
    /**
     * Flushes contents to on-disk dirnode object
     * @return true on success
     */
    bool flush()
    {
        return dnode_fpath ? DirNode::write(this, this->dnode_fpath->c_str())
                           : false;
    }

    friend encoded_fname_t * crypto_add_file(DirNode * fb, const char * fname);
    friend char * crypto_get_fname(DirNode * fb,
                                   const encoded_fname_t * codename);
    friend encoded_fname_t * crypto_add_file(DirNode * fb, const char * fname);
    friend encoded_fname_t * crypto_get_codename(DirNode * fb,
                                                 const char * plain_filename);
    friend encoded_fname_t * crypto_remove_file(DirNode * fb,
                                                const char * plain_filename);
    friend void crypto_list_files(DirNode * fb);

};
