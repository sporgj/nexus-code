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

    // if we are not at the end of the file and we have read mode on
    if (offset < file_ptr->filesize && file_ptr->flags & O_RDONLY) {
        chunk->size = min(NEXUS_CHUNK_SIZE, file_ptr->filesize - offset);

        if (nexus_fuse_fetch_chunk(file_ptr, chunk)) {
            __free_file_chunk(chunk);
            log_error("nexus_fuse_fetch_chunk FAILED\n");
            return NULL;
        }
    }

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


    pthread_rwlock_rdlock(&file_ptr->io_lock);

    if (file_ptr->filesize == 0) {
        *output_buflen = 0;
        pthread_rwlock_unlock(&file_ptr->io_lock);
        return 0;
    }


    do {
        size_t              nbytes = 0;
        size_t              len    = min(size, NEXUS_CHUNK_SIZE);

        struct file_chunk * chunk  = __file_load_chunk(file_ptr, offset);

        if (chunk == NULL) {
            log_error("chunk not found (file=%s [%d], offset=%zu, filesize=%zu)\n",
                      file_ptr->filepath, file_ptr->fid, offset, file_ptr->filesize);
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

int
file_write(struct my_file * file_ptr,
           size_t           offset,
           size_t           size,
           uint8_t        * input_buffer,
           size_t         * bytes_written)
{
    size_t total_bytes = 0;
    size_t curpos      = offset;

    pthread_rwlock_wrlock(&file_ptr->io_lock);

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

    if (curpos > file_ptr->filesize) {
        file_ptr->filesize = curpos;
    }

    file_set_dirty(file_ptr);


    // printf("file write filepath=%s [%d], offset=%zu, bytes_written=%zu, filesize=%zu\n",
    //         file_ptr->filepath, file_ptr->fid, offset, *bytes_written, file_ptr->filesize);

    pthread_rwlock_unlock(&file_ptr->io_lock);

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

    file_ptr->filesize = file_ptr->inode->attrs.posix_stat.st_size;

    INIT_LIST_HEAD(&file_ptr->file_chunks);

    pthread_rwlock_init(&file_ptr->io_lock, NULL);

    return file_ptr;
}

void
file_close(struct my_file * file_ptr)
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
