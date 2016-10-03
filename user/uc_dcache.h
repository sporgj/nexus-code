#pragma once

void dcache_init();

struct dirnode * dcache_get(const char * path);

struct dirnode * dcache_get_dir(const char * path);

void dcache_put(struct dirnode * dn);
