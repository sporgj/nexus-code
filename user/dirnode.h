#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include <google/protobuf/repeated_field.h>

extern "C" {
#include "types.h"
}
#include "dnode.pb.h"

using std::string;
using std::fstream;

class dnode;

class DirNode {
private:
    dnode_header_t header;
    dnode * proto = nullptr;
    string * dnode_fpath = nullptr;

    /**
     * Private constructor static constructor
     * @param fb is the dnode object
     * @param fd is the file stream object
     */
    DirNode(dnode * fb) { this->proto = fb; };

    const encoded_fname_t * __add_entry(const char * fname,
                                        const encoded_fname_t * p_encoded_name,
                                        bool is_file);
    encoded_fname_t * __rm_entry(const char * realname, bool is_file);
    char * __enc2raw(const encoded_fname_t * encoded_name, bool use_malloc,
                     bool is_file);
    const encoded_fname_t * __raw2enc(const char * realname, bool is_file);

public:
    DirNode();

    inline void dump()
    {
        if (dnode_fpath) {
            std::cout << dnode_fpath->c_str() << std::endl;
        }
        std::cout << proto->DebugString() << std::endl;
    }

    const encoded_fname_t * find_dir_by_raw_name(const char * rawname)
    {
        return this->__raw2enc(rawname, false);
    }

    static DirNode * from_file(const char * fpath);
    static DirNode * from_afs_fpath(const char * fpath, bool omit_last = true);
    static DirNode * load_default_dnode();
    static DirNode * lookup_path(const char * path, bool omit_last = true);

    static bool write(DirNode * fb, fstream * fd);
    static bool write(DirNode * fb, const char * fpath);

    const encoded_fname_t * add_file(const char * filename,
                                     const encoded_fname_t * p_encoded_name
                                     = nullptr);
    const encoded_fname_t * add_dir(const char * filename,
                                    const encoded_fname_t * p_encoded_name
                                    = nullptr);

    encoded_fname_t * rm_file(const char * realname);
    encoded_fname_t * rm_dir(const char * realname);

    encoded_fname_t * rename_file(const char * oldname, const char * newname);
    char * encoded2raw(const encoded_fname_t * encoded_name,
                       bool use_malloc = false);
    const encoded_fname_t * raw2encoded(const char * realname);
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

    const char * get_fpath()
    {
        return dnode_fpath ? dnode_fpath->c_str() : nullptr;
    }
};
