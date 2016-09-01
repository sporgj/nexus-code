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
    file_header_t header;
    dnode * proto = nullptr;
    string * dnode_fpath = nullptr;

    /**
     * Private constructor static constructor
     * @param fb is the dnode object
     * @param fd is the file stream object
     */
    DirNode(dnode * fb) { this->proto = fb; };

public:
    DirNode();

    inline void dump() { std::cout << proto->DebugString() << std::endl; }

    static DirNode * from_file(const char * fpath);
    static DirNode * from_afs_fpath(const char * fpath);
    static bool write(DirNode * fb, fstream * fd);
    static bool write(DirNode * fb, const char * fpath);

    encoded_fname_t * add_file(const char * filename);
    encoded_fname_t * rm_file(const char * encoded_name);
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
