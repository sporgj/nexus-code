#pragma once

struct dirnode * dcache_get(const char * path);

struct dirnode * dcache_get_dir(const char * path);

void dcache_put(struct dirnode * dn);

void dcache_rm(const sds dirpath);
