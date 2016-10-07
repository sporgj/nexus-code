#pragma once
#include "uc_dirnode.h"
#include "uc_filebox.h"

uc_dirnode_t *
dcache_get(const char * path);

uc_dirnode_t *
dcache_get_dir(const char * path);

void
dcache_put(uc_dirnode_t * dn);

void
dcache_rm(const char * dirpath);

uc_filebox_t *
dcache_get_filebox(const char * path);
