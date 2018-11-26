#include "nexus_fuse.h"

#include <stdint.h>

#include <assert.h>

#include <nexus_hashtable.h>


static struct nexus_hashtable * inode_cache      = NULL;

static struct my_dentry       * root_dentry      = NULL;

static struct my_inode        * root_inode       = NULL;


static struct my_inode *
__icache_alloc(fuse_ino_t ino, struct nexus_uuid * uuid);


static uint32_t
hash_from_key_fn(uintptr_t k)
{
    return (uint32_t) k; // our keys are fuse_ino_t (which are uint64_t)
}

static int
keys_equal_fn(uintptr_t key1, uintptr_t key2)
{
    return ((fuse_ino_t)key1) == ((fuse_ino_t)key2);
}

int
vfs_init()
{
    inode_cache = nexus_create_htable(256, hash_from_key_fn, keys_equal_fn);

    if (inode_cache == NULL) {
        log_error("nexus_create_hashtable FAILED\n");
        return -1;
    }

    root_dentry = dentry_create(NULL, "", NEXUS_DIR);
    root_inode  = __icache_alloc(FUSE_ROOT_ID, NULL);

    root_inode->lookup_count = 1;

    dentry_instantiate(root_dentry, root_inode);

    return 0;
}

void
vfs_deinit()
{
    // TODO iterate through all the inodes and dentries
    if (inode_cache) {
        nexus_free_htable(inode_cache, 1, 0);
    }
}

static struct my_inode *
__icache_alloc(fuse_ino_t ino, struct nexus_uuid * uuid)
{
    struct my_inode * inode = nexus_malloc(sizeof(struct my_inode));

    inode->ino = ino;

    INIT_LIST_HEAD(&inode->dentry_list);

    if (uuid) {
        nexus_uuid_copy(uuid, &inode->uuid);
    }

    assert(nexus_htable_insert(inode_cache, (uintptr_t)inode->ino, (uintptr_t)inode)
           != (uintptr_t)NULL);

    return inode;
}


static inline struct my_inode *
icache_find(fuse_ino_t ino)
{
    return nexus_htable_search(inode_cache, (uintptr_t)ino);
}

static inline void
icache_del(fuse_ino_t ino)
{
    struct my_inode * inode = NULL;

    inode = (struct my_inode *) nexus_htable_remove(inode_cache, (uintptr_t)ino, 0);

    if (inode) {
        nexus_free(inode);
    }
}

struct my_inode *
vfs_get_inode(fuse_ino_t ino)
{
    return icache_find(ino);
}

struct my_dentry *
vfs_get_dentry(fuse_ino_t ino)
{
    struct my_inode * inode = icache_find(ino);

    if (inode && inode->dentry_count) {
        return list_first_entry(&inode->dentry_list, struct my_dentry, aliases);
    }

    return NULL;
}

struct my_dentry *
_vfs_cache_dentry(struct my_dentry * parent, char * name, struct nexus_fs_lookup * lookup_info)
{
    fuse_ino_t  ino = nexus_uuid_hash(&lookup_info->uuid);

    struct my_inode  * inode  = icache_find(ino);
    struct my_dentry * dentry = dentry_lookup(parent, name);


    if (inode == NULL) {
        inode = __icache_alloc(ino, &lookup_info->uuid);
    }

    if (dentry == NULL) {
        dentry = dentry_create(parent, name, lookup_info->type);
    }

    memcpy(&dentry->lookup_info, lookup_info, sizeof(struct nexus_fs_lookup));
    dentry_instantiate(dentry, inode);

    return dentry;
}

struct my_dentry *
vfs_cache_dentry(struct my_dentry  * parent,
                 char              * name,
                 struct nexus_uuid * uuid,
                 nexus_dirent_type_t type)
{
    struct nexus_fs_lookup lookup_info = { .type = type };

    nexus_uuid_copy(uuid, &lookup_info.uuid);

    return _vfs_cache_dentry(parent, name, &lookup_info);
}

void
vfs_forget_dentry(struct my_dentry * parent_dentry, char * name)
{
    struct my_dentry * child = dentry_lookup(parent_dentry, name);

    if (child) {
        dentry_invalidate(child);
    }
}

void
vfs_remove_inode(struct my_inode * inode)
{
    struct list_head * curr = NULL;

    if (inode == NULL || inode->lookup_count) {
        return;
    }

    list_for_each(curr, &inode->dentry_list) {
        struct my_dentry * dentry = list_entry(curr, struct my_dentry, aliases);

        dentry_invalidate(dentry);
    }

    icache_del(inode->ino);
}



// TODO add directory to open directories
struct my_dir *
vfs_dir_alloc(struct my_dentry * dentry)
{
    struct my_dir * dir_ptr = nexus_malloc(sizeof(struct my_dir));

    dir_ptr->dentry  = dentry_get(dentry);
    dir_ptr->dirpath = dentry_get_fullpath(dentry);

    return dir_ptr;
}

void
vfs_dir_free(struct my_dir * dir_ptr)
{
    dentry_put(dir_ptr->dentry);
    nexus_free(dir_ptr->dirpath);
    nexus_free(dir_ptr);
}




void
inode_incr_lookup(struct my_inode * inode, uint64_t count)
{
    inode->lookup_count += count;
}

void
inode_decr_lookup(struct my_inode * inode, uint64_t count)
{
    assert(inode->lookup_count >= count);

    inode->lookup_count -= count;

    if (inode->lookup_count == 0) {
        vfs_remove_inode(inode);
    }
}


static inline size_t
get_chunk_number(size_t offset)
{
    return ((offset < NEXUS_CHUNK_SIZE)
                ? 0
                : 1 + ((offset - NEXUS_CHUNK_SIZE) >> NEXUS_CHUNK_LOG2));
}

static inline size_t
get_base_offset(size_t offset)
{
    return get_chunk_number(offset) * NEXUS_CHUNK_SIZE; // XXX multiple of 2
}



static struct file_chunk *
__alloc_file_chunk(size_t base)
{
    struct file_chunk * chunk = nexus_malloc(sizeof(struct file_chunk));

    chunk->base   = base;
    chunk->index  = get_chunk_number(base);
    chunk->buffer = nexus_malloc(NEXUS_CHUNK_SIZE);

    INIT_LIST_HEAD(&chunk->node);

    return chunk;
}

static void
__free_file_chunk(struct file_chunk * chunk)
{
    nexus_free(chunk->buffer);
    nexus_free(chunk);
}

// returns the number of bytes written in the block
static size_t
__update_file_chunk(struct file_chunk * chunk, size_t offset, size_t len, uint8_t * input_buffer)
{
    assert(offset <= chunk->base + NEXUS_CHUNK_SIZE);

    size_t shift = offset - chunk->base;

    size_t nbytes = min(len, (NEXUS_CHUNK_SIZE - shift));

    memcpy(chunk->buffer + shift, input_buffer, nbytes);

    chunk->size = nbytes + shift;

    return nbytes;
}

// returns the number of bytes read
static size_t
__read_file_chunk(struct file_chunk * chunk, size_t offset, size_t len, uint8_t * output_buffer)
{
    assert(offset <= chunk->base + NEXUS_CHUNK_SIZE);

    size_t shift = offset - chunk->base;

    size_t nbytes = min(len, (NEXUS_CHUNK_SIZE - shift));

    memcpy(output_buffer, chunk->buffer + shift, nbytes);

    return nbytes;
}

static struct file_chunk *
__file_find_chunk(struct my_file * file, size_t offset)
{
    struct list_head * curr = NULL;

    size_t base = get_base_offset(offset);

    list_for_each(curr, &file->file_chunks) {
        struct file_chunk * chunk = list_entry(curr, struct file_chunk, node);

        if (base == chunk->base) {
            return chunk;
        }
    }

    return NULL;
}

static struct file_chunk *
__file_try_add_chunk(struct my_file * file_ptr, size_t offset)
{
    struct file_chunk * chunk = __file_find_chunk(file_ptr, offset);

    if (chunk) {
        return chunk;
    }

    chunk = __alloc_file_chunk(get_base_offset(offset));

    list_add_tail(&chunk->node, &file_ptr->file_chunks);

    file_ptr->chunk_count += 1;

    return chunk;
}

static struct file_chunk *
__file_load_chunk(struct my_file * file_ptr, size_t offset)
{
    struct file_chunk * chunk = NULL;

    if (offset >= file_ptr->filesize) {
        log_error("trying to read past file size (path=%s, filesize=%zu, offset=%zu)\n",
                  file_ptr->filepath, file_ptr->filesize, offset);
        return NULL;
    }

    chunk = __file_try_add_chunk(file_ptr, offset);

    if (chunk->is_valid) {
        return chunk;
    }

    chunk->size = min(NEXUS_CHUNK_SIZE, (file_ptr->filesize - offset));

    if (nexus_fuse_fetch_chunk(file_ptr, chunk)) {
        log_error("nexus_fuse_fetch_chunk FAILED\n");
        return NULL;
    }

    chunk->is_valid = true;
    chunk->is_dirty = false;

    return chunk;
}

int
file_read(struct my_file * file_ptr,
          size_t           offset,
          size_t           size,
          uint8_t        * output_buffer,
          size_t         * output_buflen)
{
    size_t total_bytes = 0;

    if (file_ptr->filesize == 0) {
        *output_buflen = 0;
        return 0;
    }


    do {
        size_t              nbytes = 0;
        size_t              len    = min(size, NEXUS_CHUNK_SIZE);

        struct file_chunk * chunk  = __file_load_chunk(file_ptr, offset);

        if (chunk == NULL) {
            log_error("chunk not found (file=%s, offset=%zu, filesize=%zu)\n",
                      file_ptr->filepath, offset, file_ptr->filesize);
            return -1;
        }

        nbytes = __read_file_chunk(chunk, offset, len, output_buffer);

        output_buffer += nbytes;
        total_bytes   += nbytes;
        offset        += nbytes;
        size          -= nbytes;
    } while(size > 0);

    *output_buflen = total_bytes;

    return 0;
}

int
file_write(struct my_file * file_ptr,
           size_t           offset,
           size_t           size,
           uint8_t        * input_buffer,
           size_t         * bytes_read)
{
    size_t total_bytes = 0;

    do {
        size_t              nbytes = 0;
        size_t              len    = min(size, NEXUS_CHUNK_SIZE);

        struct file_chunk * chunk  = __file_try_add_chunk(file_ptr, offset);

        if (chunk == NULL) {
            log_error("chunk not found (file=%s, offset=%zu)\n", file_ptr->filepath, offset);
            return -1;
        }

        nbytes = __update_file_chunk(chunk, offset, len, input_buffer);

        input_buffer += nbytes;
        total_bytes  += nbytes;
        size         -= nbytes;
        offset       += nbytes;
    } while(size > 0);

    *bytes_read = total_bytes;

    if (offset > file_ptr->filesize) {
        file_ptr->filesize = offset;
    }

    file_set_dirty(file_ptr);

    return 0;
}

void
file_set_clean(struct my_file * file_ptr)
{
    file_ptr->is_dirty = false;
}

void
file_set_dirty(struct my_file * file_ptr)
{
    file_ptr->is_dirty = true;
}


// TODO add file to list of open files
struct my_file *
vfs_file_alloc(struct my_dentry * dentry)
{
    struct my_file * file_ptr = nexus_malloc(sizeof(struct my_file));

    file_ptr->dentry   = dentry_get(dentry);
    file_ptr->filepath = dentry_get_fullpath(dentry);
    file_ptr->inode    = file_ptr->dentry->inode;

    file_ptr->filesize = file_ptr->inode->attrs.posix_stat.st_size;

    INIT_LIST_HEAD(&file_ptr->file_chunks);

    return file_ptr;
}

void
vfs_file_free(struct my_file * file_ptr)
{
    struct file_chunk * chunk = NULL;

    while (!list_empty(&file_ptr->file_chunks)) {
        chunk = list_first_entry(&file_ptr->file_chunks, struct file_chunk, node);

        list_del(&chunk->node);

        __free_file_chunk(chunk);
    }

    dentry_put(file_ptr->dentry);
    nexus_free(file_ptr->filepath);
    nexus_free(file_ptr);
}
