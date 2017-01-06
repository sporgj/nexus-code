#include "uc_fcache.h"

static Hashmap * dirnode_dirty_table, * dirnode_clean_table;

static void __flush_dirty_entries()
{

}

static int __hash_dirnode(void * key)
{
	return ((uc_dirnode_t *)key)->header.uuid;
}
