#include <iostream>
#include <fstream>

#include "uspace.h"

map<string, SuperNode *> Supernode::objs = new map<string, SuperNode *>();

SuperNode * add_cell(char * cell, char * fpath)
{
    SuperNode * _obj;

    if (objs->size() > UCAFS_MAX_CELLS) {
        return nullptr;
    }

    _obj = new SuperNode();
    _obj->proto = new class::snode;

    // parse the file
    fstream input(fpath, ios::in | ios::bin);
    if (input && _obj->proto->ParseFromIStream(&input)) {;
        // add it to our map and go
        map[cell] = _obj;
    }
    input.close();

    return _obj;
}
