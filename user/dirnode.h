#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include <google/protobuf/repeated_field.h>

extern "C" {
#include "types.h"
}
#include "dnode.pb.h"
#include "afsx_hdr.h"

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

public:
    DirNode();

    /**
     * Open the dirnode at following fpath
     * @param fpath: fullpath to the dirnode file
     * @return nullptr if there's an error parsing the file
     */
    static DirNode * from_file(const char * fpath);

    /**
     * Loads the default dnode from the repository
     * @return the dirnode object
     */
    static DirNode * load_default_dnode();

    /**
     * Writes the entry to disk. Could write by file descriptor or path
     */
    static bool write(DirNode * dnode, fstream * fd);
    static bool write(DirNode * dnode, const char * fpath);

    /**
     * Adds a new entry to the dirnode
     * @param name is the name of the object to be add
     * @param type is the type of the object
     * @param {optional} p_encoded_name if the user already has an encoded name
     * return nullptr if an error occurs
     */
    const encoded_fname_t * add(const char * name, ucafs_entry_type type,
                                const encoded_fname_t * p_encoded_name
                                = nullptr);

    /**
     * Removes the entry in the dirnode
     * @param rawname is the raw name of the object
     * @return null if the entry is not found
     */
    const encoded_fname_t * rm(const char * rawname,
                               ucafs_entry_type type = UCAFS_TYPE_UNKNOWN);

    /**
     * Using the encoded name, find the corresponding raw string
     * @param encoded_name is the encoded name to look for
     * @return a string of the name
     */
    const char * enc2raw(const encoded_fname_t * encoded_name,
                        ucafs_entry_type type = UCAFS_TYPE_UNKNOWN);

    /**
     * Finds the entry inside the dirnode
     * @param rawname is the entry's raw name
     * @return the encoded file name
     */
    const encoded_fname_t * raw2enc(const char * rawname,
                                 ucafs_entry_type type = UCAFS_TYPE_UNKNOWN);

    /**
     * Renaming entryin the old with the new
     * @param oldname
     * @param newname is the new name
     * @param type is type of entry being changed
     */
    const encoded_fname_t * rename(const char * oldname, const char * newname,
                                   ucafs_entry_type type);

    /**
     * Flushes contents to on-disk dirnode object
     * @return true on success
     */
    bool flush()
    {
        return dnode_fpath ? DirNode::write(this, this->dnode_fpath->c_str())
                           : false;
    }

    bool operator==(const DirNode & d);
#ifdef UCAFS_DEBUG
    void list_files();

    inline void dump()
    {
        if (dnode_fpath) {
            std::cout << dnode_fpath->c_str() << std::endl;
        }
        std::cout << proto->DebugString() << std::endl;
    }

    const char * get_fpath()
    {
        return dnode_fpath ? dnode_fpath->c_str() : nullptr;
    }
#endif
};
