#include "uc_filebox.h"
#include "uc_sgx.h"

#include "third/log.h"

uc_filebox_t *
filebox_new2(const shadow_t * id, uc_dirnode_t * dirnode)
{
    uc_filebox_t * filebox = (uc_filebox_t *)calloc(1, sizeof(uc_filebox_t));
    if (filebox == NULL) {
        log_fatal("allocation failed");
        return NULL;
    }
    
    /* generate our ID */
    if (id) {
        memcpy(&filebox->header.uuid, id, sizeof(shadow_t));
    } else {
        uuid_generate_time_safe((uint8_t *)&filebox->header.uuid);
    }

    filebox->header.chunk_count = filebox->allocated = 1;
    filebox->header.chunk_size_log2 = UCAFS_CHUNK_LOG;

    /* initialize chunk0 */
    filebox->chunk0 = (filebox_chunk_entry_t *)calloc(1, sizeof(filebox_chunk_entry_t));
    if (filebox->chunk0 == NULL) {
        log_fatal("allocation error");
        free(filebox);
    }

    TAILQ_INIT(&filebox->chunk_list);
    TAILQ_INSERT_HEAD(&filebox->chunk_list, filebox->chunk0, next_entry);

    /* last, just set the root */
    if (dirnode) {
        memcpy(&filebox->header.root, &dirnode->header.root, sizeof(shadow_t));
    }

    return filebox;
}

// TODO inline this in the header
uc_filebox_t *
filebox_new()
{
    return filebox_new2(NULL, NULL);
}

static inline void
filebox_free_payload(uc_filebox_t * filebox)
{
    if (filebox->payload) {
        free(filebox->payload);
        filebox->payload = NULL;
    }
}

void
filebox_free(uc_filebox_t * filebox)
{
    filebox_chunk_entry_t * chunk_entry;
    filebox_chunk_head_t * chunk_list = &filebox->chunk_list;

    while ((chunk_entry = TAILQ_FIRST(chunk_list))) {
        TAILQ_REMOVE(chunk_list, chunk_entry, next_entry);
        free(chunk_entry);
    }

    if (filebox->payload) {
        free(filebox->payload);
    }

    if (filebox->fbox_path) {
        sdsfree(filebox->fbox_path);
    }
}

uc_filebox_t *
filebox_from_file(const sds filepath)
{
    uc_filebox_t * filebox;
    filebox_header_t * header;
    filebox_chunk_t * fbox_chunk;
    filebox_chunk_entry_t * chunk_entry;
    filebox_chunk_head_t * chunk_list;
    FILE * fd;
    int ret = -1;
    size_t nbytes, size;

    fd = fopen(filepath, "rb");
    if (fd == NULL) {
        log_error("opening '%s' failed", filepath);
        return NULL;
    }

    if ((filebox = calloc(1, sizeof(uc_filebox_t))) == NULL) {
        log_fatal("allocation failure");
        return NULL;
    }

    /* initialize the necessary variables */
    header = &filebox->header;
    chunk_list = &filebox->chunk_list;

    TAILQ_INIT(chunk_list);

    /* read in the header and allocate the necessary buffers */
    nbytes = fread(header, 1, sizeof(filebox_header_t), fd);
    if (nbytes != sizeof(filebox_header_t)) {
        log_error("reading header: %s (nbytes=%zu, exp=%lu)", filepath, nbytes,
                  sizeof(filebox_header_t));
        goto out;
    }

    if ((filebox->payload = calloc(1, header->fbox_payload_len)) == NULL) {
        log_fatal("allocation error");
        goto out;
    }

    /* copy the payload information into memory */
    nbytes = fread(filebox->payload, 1, header->fbox_payload_len, fd);
    if (nbytes != header->fbox_payload_len) {
        log_error("reading payload: %s (nbytes=%zu, exp=%lu)", filepath, nbytes,
                  sizeof(header->fbox_payload_len));
        goto out;
    }

#ifdef UCAFS_SGX
    /* decrypt the content with enclave */
    int error;
    ecall_filebox_crypto(global_eid, &error, filebox, UC_DECRYPT);
    if (error) {
        log_error("enclave dirnode decryption failed");
        goto out;
    }
#endif

    /* parse the chunk entries */
    fbox_chunk = (filebox_chunk_t *)filebox->payload;
    for (size_t i = 0; i < header->chunk_count; i++) {
        // XXX employ the "freeable chunk" concept from dirnode
        if ((chunk_entry = calloc(1, sizeof(filebox_chunk_entry_t))) == NULL) {
            log_fatal("allocation failure");
            goto out;
        }

        memcpy(&chunk_entry->chunk, fbox_chunk, sizeof(filebox_chunk_t));
        TAILQ_INSERT_TAIL(chunk_list, chunk_entry, next_entry);

        filebox->allocated++;
        fbox_chunk++;
    }

    // setup chunk0 and the path of the metadata file
    filebox->chunk0 = TAILQ_FIRST(chunk_list);
    filebox->fbox_path = sdsdup(filepath);

    ret = 0;
out:
    fclose(fd);
    /* no need to hold the payload buffer for so long */
    filebox_free_payload(filebox);

    if (ret) {
        filebox_free(filebox);
        filebox = NULL;
    }

    return filebox;
}

bool
filebox_write(uc_filebox_t * filebox, const char * fpath)
{
    int error;
    bool ret = false;
    size_t nbytes;
    FILE * fd;
    filebox_chunk_t * fbox_chunk;
    filebox_header_t * header = &filebox->header;
    filebox_chunk_entry_t *chunk0, *chunk_entry;

    /* check if file exists */
    if ((fd = fopen(fpath, "wb")) == NULL) {
        log_error("opening '%s' failed", fpath);
        return -1;
    }

    /* serialize chunks into the payload */
    header->fbox_payload_len = header->chunk_count * sizeof(filebox_chunk_t);
    if ((filebox->payload = calloc(1, header->fbox_payload_len)) == NULL) {
        log_fatal("allocation error");
        goto out;
    }

    fbox_chunk = (filebox_chunk_t *)filebox->payload;
    chunk_entry = TAILQ_FIRST(&filebox->chunk_list);
    for (size_t i = 0; i < header->chunk_count; i++) {
        memcpy(fbox_chunk, &chunk_entry->chunk, sizeof(filebox_chunk_t));

        fbox_chunk++;
        chunk_entry = TAILQ_NEXT(chunk_entry, next_entry);
    }

#ifdef UCAFS_SGX
    /* decrypt the content with enclave */
    ecall_filebox_crypto(global_eid, &error, filebox, UC_ENCRYPT);
    if (error) {
        log_error("enclave filebox encryption failed");
        goto out;
    }
#endif

    /* write output to file and close */
    nbytes = fwrite(header, 1, sizeof(filebox_header_t), fd);
    if (nbytes != sizeof(filebox_header_t)) {
        log_error("reading header: %s (nbytes=%zu, exp=%lu)", fpath, nbytes,
                  sizeof(filebox_header_t));
        goto out;
    }

    nbytes = fwrite(filebox->payload, 1, header->fbox_payload_len, fd);
    if (nbytes != header->fbox_payload_len) {
        log_error("reading payload: %s (nbytes=%zu, exp=%lu)", fpath, nbytes,
                  sizeof(header->fbox_payload_len));
        goto out;
    }

    ret = true;
out:
    fclose(fd);
    filebox_free_payload(filebox);

    return ret;
}

// XXX inline this
bool
filebox_flush(uc_filebox_t * fb)
{
    return fb->fbox_path ? filebox_write(fb, fb->fbox_path) : false;
}

void
filebox_set_size(uc_filebox_t * filebox, size_t size)
{
    filebox_chunk_entry_t * chunk_entry;
    int nchunks = UCAFS_CHUNK_COUNT(size), todo;

    /* make sure the number of allocated chunks suffice */
    if (nchunks > filebox->header.chunk_count) {
        /* set the appropriate file and chunk count */
        filebox->header.chunk_count = nchunks;
        filebox->header.file_size = size;

        filebox_chunk_head_t * chunk_list = &filebox->chunk_list;

        // do we need to allocate more
        todo = nchunks - (int)filebox->allocated;
        while (todo > 0) {
            // XXX employ the "freeable chunk" concept from dirnode
            chunk_entry = calloc(1, sizeof(filebox_chunk_entry_t));
            if (chunk_entry == NULL) {
                // TODO memory leak here, add assertion
                log_fatal("allocation failure");
                return;
            }

            TAILQ_INSERT_TAIL(chunk_list, chunk_entry, next_entry);

            todo--;
            filebox->allocated++;
        }
    }
}
