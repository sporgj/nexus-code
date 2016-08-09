#pragma once
#include <string>
#include <iostream>
#include <fstream>

extern "C" {
#include "types.h"
}
#include "fbox.pb.h"

using std::string;
using std::fstream;

class fbox;

class FileBox {
private:
    fbox * fbox_ptr;
    fstream * fd;

    /**
     * Private constructor static constructor
     * @param fb is the fbox object
     * @param fd is the file stream object
     */
    FileBox(fbox * fb)
    {
        this->fbox_ptr = fb;
    };

public:
    FileBox();
    inline void set_ekey(crypto_ekey_t * ekey)
    {
        fbox_ptr->set_ekey(ekey, sizeof(crypto_ekey_t));
    }

    inline void set_mac(crypto_mac_t * mac)
    {
        fbox_ptr->set_mac(mac, sizeof(crypto_mac_t));
    }

    inline void dump()
    {
        std::cout << fbox_ptr->DebugString() << std::endl;
    }

    static FileBox * from_file(const char * fpath, bool readonly);
    static bool write(FileBox * fb, fstream * fd);
    static bool write(FileBox * fb, const char * fpath);
    
    bool add(encoded_fname_t * encoded_fname, raw_fname_t * fname,
             crypto_iv_t * iv);

    friend encoded_fname_t * crypto_add_file(FileBox * fb, const char * fname);
    friend char * crypto_get_fname(FileBox * fb,
                                   const encoded_fname_t * codename);
    friend encoded_fname_t * crypto_add_file(FileBox * fb, const char * fname);
    friend encoded_fname_t * crypto_get_codename(FileBox * fb,
                                                 const char * plain_filename);
};
