struct __filldir_entry {
    char                   * dirpath;

    struct nexus_uuid        stat_uuid;

    size_t                   curr_offset;

    size_t                   total_count;

    struct nexus_hashtable * hashmap;
};


struct filldir_cache {
    struct nexus_hashtable * hashmap;

    struct sgx_backend     * sgx_backend;
};

uint32_t
string_hash(uintptr_t stringkey)
{
    char * str = (char *)stringkey;

    unsigned int c, hash = FNV32_BASE;
    while ((c = (unsigned char)*str++)) {
        if (c >= 'a' && c <= 'z')
            c -= 'a' - 'A';
        hash = (hash * FNV32_PRIME) ^ c;
    }
    return hash;
}

int
string_equal(uintptr_t key1, uintptr_t key2)
{
    char * str1 = (char *)key1;
    char * str2 = (char *)key2;

    return (strncmp(str1, str2, NEXUS_PATH_MAX) == 0);
}

struct filldir_cache *
filldir_cache_init()
{
    struct filldir_cache * filldir_cache = nexus_malloc(sizeof(struct filldir_cache));

    filldir_cache->hashmap = nexus_create_htable(16, string_hash, string_equal);

    return filldir_cache;
}

void
filldir_cache_destroy(struct filldir_cache * filldir_cache)
{
    nexus_free_htable(filldir_cache->hashmap, 1, 1);

    nexus_free(filldir_cache);
}

int
__readdir_dirnode(struct __filldir_entry * entry, char * dirpath)
{
    int ret = -1;
}

struct __filldir_entry *
__cache_new_filldir_entry(struct filldir_cache * filldir_cache, char * dirpath)
{
    struct __filldir_entry * fentry = nexus_malloc(sizeof(struct __filldir_entry));

    fentry->hashmap = nexus_create_htable(16, string_hash, string_equal);

    fentry->dirpath = strndup(dirpath, NEXUS_MAX_PATH);

    return fentry;
}

char *
filldir_cache_filldir(struct filldir_cache * filldir_cache, char * dirpath, char * nexus_name)
{
    struct __filldir_entry * fentry = NULL;

    // 1 - check the filldir hashtable
    fentry = nexus_htabl_search(filldir_cache->hashmap, (uintptr_t) dirpath);

    if (fentry == NULL) {
        fentry = __cache_new_filldir_entry(dirpath);
    }

    // 2 - if it exists, perform the lookup
    //
    // 3 - otherwise, cache and perform the lookup
}
