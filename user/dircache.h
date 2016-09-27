#pragma once
#include <string>
#include "dirnode.h"

using std::string;

struct dirent {
    const char * dnode_name;
    uint16_t ref; // number of references
};

/**
 * Using the path passed, looks for dirnode entry that corresponds
 * to the path.
 * @param path is the path to the object
 * @return dentry to the containing parent
 */
struct DirNode * dcache_get_dirnode(const char * path);

void dcache_put(struct DirNode * dirnode);
