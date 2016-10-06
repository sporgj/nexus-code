#pragma once

uc_dirnode_t * dcache_get(const char * path);

uc_dirnode_t * dcache_get_dir(const char * path);

void dcache_put(uc_dirnode_t * dn);

void dcache_rm(const char * dirpath);
