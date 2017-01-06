#pragma once
#include "uc_dirnode.h"
#include "uc_filebox.h"

uc_dirnode_t * icache_get_dirnode(const shadow_t * shdw_name);
void icache_set_dirnode_dirty(const uc_dirnode_t * dirnode);
