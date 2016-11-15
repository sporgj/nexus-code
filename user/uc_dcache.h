#pragma once
#include "uc_dirnode.h"
#include "uc_filebox.h"

uc_dirnode_t *
dcache_lookup(const char * path, bool dirpath);

void
dcache_put(uc_dirnode_t * dn);

void
dcache_rm(uc_dirnode_t * dn);

uc_filebox_t *
dcache_get_filebox(const char * path);
