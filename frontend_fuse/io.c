#include "nexus_fuse.h"

#include <assert.h>


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
    chunk->buffer = valloc(NEXUS_CHUNK_SIZE);

    INIT_LIST_HEAD(&chunk->node);

    return chunk;
}

void
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

    chunk->is_dirty = true;

    inode_set_dirty(chunk->inode);

    return nbytes;
}

static uint8_t *
__get_readable_file_chunk(struct file_chunk * chunk,
                          size_t              offset,
                          size_t              len,
                          size_t            * readable_bytes)
{
    assert(offset <= chunk->base + NEXUS_CHUNK_SIZE);

    size_t shift = offset - chunk->base;

    *readable_bytes = min(len, (NEXUS_CHUNK_SIZE - shift));

    return (chunk->buffer + shift);
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
__file_find_chunk(struct my_file * file_ptr, size_t offset)
{
    struct my_inode * inode = file_ptr->dentry->inode;

    struct list_head * curr = NULL;

    size_t base = get_base_offset(offset);

    list_for_each(curr, &inode->file_chunks) {
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
    struct my_inode   * inode = file_ptr->inode;

    struct file_chunk * chunk = __file_find_chunk(file_ptr, offset);

    if (chunk) {
        return chunk;
    }

    // allocate the chunk and add to the inode list
    chunk = __alloc_file_chunk(get_base_offset(offset));

    if (chunk->base < inode->on_disk_size) {
        chunk->size = min(NEXUS_CHUNK_SIZE, inode->filesize - offset);

        if (nexus_fuse_fetch_chunk(file_ptr, chunk)) {
            __free_file_chunk(chunk);
            log_error("nexus_fuse_fetch_chunk FAILED\n");
            return NULL;
        }
    }

    pthread_mutex_lock(&inode->lock);
    list_add_tail(&chunk->node, &inode->file_chunks);

    inode->chunk_count += 1;
    pthread_mutex_unlock(&inode->lock);

    chunk->inode = inode;

    chunk->is_valid = true;

    return chunk;
}

static struct file_chunk *
__file_load_chunk(struct my_file * file_ptr, size_t offset)
{
    struct file_chunk * chunk = NULL;

    if (offset >= file_ptr->inode->filesize && !(file_ptr->flags & O_WRONLY)) {
        log_error("trying to read past file size (path=%s, filesize=%zu, offset=%zu)\n",
                  file_ptr->filepath,
                  file_ptr->inode->filesize,
                  offset);
        return NULL;
    }

    chunk = __file_try_add_chunk(file_ptr, offset);

    if (chunk == NULL) {
        log_error("__file_try_add_chunk() FAILED\n");
        return NULL;
    }

    if (chunk->is_valid) {
        return chunk;
    }

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


    if (file_ptr->inode->filesize == 0) {
        *output_buflen = 0;
        return 0;
    }


    do {
        size_t              nbytes = 0;
        size_t              len    = min(size, NEXUS_CHUNK_SIZE);

        struct file_chunk * chunk  = __file_load_chunk(file_ptr, offset);

        if (chunk == NULL) {
            log_error("chunk not found (file=%s [%d], offset=%zu, filesize=%zu)\n",
                      file_ptr->filepath,
                      file_ptr->fid,
                      offset,
                      file_ptr->inode->filesize);
            pthread_rwlock_unlock(&file_ptr->io_lock);
            return -1;
        }

        nbytes = __read_file_chunk(chunk, offset, len, output_buffer);

        output_buffer += nbytes;
        total_bytes   += nbytes;
        offset        += nbytes;
        size          -= nbytes;
    } while(size > 0);

    *output_buflen = total_bytes;

    pthread_rwlock_unlock(&file_ptr->io_lock);

    return 0;
}

const uint8_t *
file_read_dataptr(struct my_file * file_ptr, size_t offset, size_t len, size_t * readable_bytes)
{
    struct file_chunk * chunk = NULL;

    if (file_ptr->inode->filesize == 0) {
        *readable_bytes = 0;
        return 0;
    }

    chunk = __file_load_chunk(file_ptr, offset);

    if (chunk == NULL) {
        log_error("chunk at offset %zu not found. filepath=%s\n", offset, file_ptr->filepath);
        return NULL;
    }

    return __get_readable_file_chunk(chunk, offset, len, readable_bytes);
}

int
file_write(struct my_file * file_ptr,
           size_t           offset,
           size_t           size,
           uint8_t        * input_buffer,
           size_t         * bytes_written)
{
    struct my_inode * inode = file_ptr->inode;

    size_t total_bytes = 0;
    size_t curpos      = offset;


    if (file_ptr->flags & O_APPEND) {
        curpos = file_ptr->offset;
    }

    do {
        size_t              nbytes = 0;
        size_t              len    = min(size, NEXUS_CHUNK_SIZE);

        struct file_chunk * chunk  = __file_try_add_chunk(file_ptr, curpos);

        if (chunk == NULL) {
            log_error("chunk not found (file=%s, offset=%zu)\n", file_ptr->filepath, curpos);
            pthread_rwlock_unlock(&file_ptr->io_lock);
            return -1;
        }

        nbytes = __update_file_chunk(chunk, curpos, len, input_buffer);

        chunk->is_valid = true;

        input_buffer += nbytes;
        total_bytes  += nbytes;
        size         -= nbytes;
        curpos       += nbytes;
    } while(size > 0);

    *bytes_written = total_bytes;

    if (file_ptr->flags & O_APPEND) {
        file_ptr->offset += total_bytes;
    }

    if (curpos > inode->filesize) {
        inode->filesize = curpos;
    }

    file_set_dirty(file_ptr);

    return 0;
}

struct my_file *
file_open(struct my_dentry * dentry, int fid, int flags)
{
    struct my_file * file_ptr = nexus_malloc(sizeof(struct my_file));

    file_ptr->fid      = fid;
    file_ptr->flags    = flags;

    file_ptr->dentry   = dentry_get(dentry);
    file_ptr->filepath = dentry_get_fullpath(dentry);
    file_ptr->inode    = file_ptr->dentry->inode;

    if (flags & O_APPEND) {
        file_ptr->offset = file_ptr->inode->filesize;
    }

    pthread_rwlock_init(&file_ptr->io_lock, NULL);

    return file_ptr;
}

void
file_close(struct my_file * file_ptr)
{
    dentry_put(file_ptr->dentry);
    nexus_free(file_ptr->filepath);
    nexus_free(file_ptr);
}
