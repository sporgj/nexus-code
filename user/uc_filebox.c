#include <stdio.h>
#include <stdlib.h>

#include "third/slog.h"
#include "third/log.h"

#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_sgx.h"
#include "uc_types.h"
#include "uc_uspace.h"
#include "uc_utils.h"

struct filebox {
    uc_fbox_t * fbox;
    sds fbox_path;
};

uc_filebox_t *
filebox_new2(shadow_t * id, uc_dirnode_t * dirnode)
{
    uc_fbox_t * fbox;
    uc_filebox_t * filebox = (uc_filebox_t *)malloc(sizeof(uc_filebox_t));
    if (filebox == NULL) {
        log_fatal("allocation error");
        return NULL;
    }

    filebox->fbox_path = NULL;

    // instantiate a default fbox
    if ((fbox = (uc_fbox_t *)calloc(1, sizeof(uc_fbox_t))) == NULL) {
        log_fatal("allocating fbox failed");
        free(filebox);
        return NULL;
    }

    fbox->chunk_count = 1;
    fbox->chunk_size = UCAFS_CHUNK_SIZE;
    fbox->fbox_len = FBOX_DEFAULT_LEN;
    fbox->file_size = 0;
    fbox->link_count = 1;

    if (id) {
        memcpy(&fbox->uuid, id, sizeof(shadow_t));
    } else {
        uuid_generate_time_safe(fbox->uuid.bin);
    }

    if (dirnode) {
        memcpy(&fbox->root, dirnode_get_root(dirnode), sizeof(shadow_t));
    }

    filebox->fbox = fbox;

    return filebox;
}

uc_filebox_t *
filebox_new()
{
    return filebox_new2(NULL, NULL);
}

uc_fbox_t *
filebox_fbox(uc_filebox_t * filebox)
{
    return filebox->fbox;
}

int
filebox_equals(const uc_filebox_t * fb1, uc_filebox_t * fb2)
{
    return memcmp(&fb1->fbox->uuid, &fb2->fbox->uuid, sizeof(uuid_t)) == 0;
}

void
filebox_free(uc_filebox_t * filebox)
{
    if (filebox->fbox_path) {
        sdsfree(filebox->fbox_path);
    }

    free(filebox->fbox);
    free(filebox);
}

uc_filebox_t *
filebox_from_file2(const sds filepath, size_t size_hint)
{
    uc_filebox_t * obj = NULL;
    fbox_header_t header;
    uc_fbox_t * fbox;
    int len, nbytes;
    uint8_t * buffer;
    FILE * fd;
    int ret = -1;

    fd = fopen(filepath, "rb");
    if (fd == NULL) {
        log_error("could not open: %s", filepath);
        return NULL;
    }

    /* read the header from the file */
    nbytes = fread(&header, sizeof(fbox_header_t), 1, fd);
    if (!nbytes) {
        log_error("could not read header: %s (nbytes=%u)", filepath, nbytes);
        goto out;
    }

    /* now detect how much data to allocate */
    len = MAX(size_hint, header.fbox_len);
    if ((fbox = (uc_fbox_t *)malloc(len)) == NULL) {
        log_fatal("allocation failed. len=%u", len);
        goto out;
    }

    memcpy(fbox, &header, sizeof(fbox_header_t));
    buffer = ((uint8_t *)fbox) + sizeof(fbox_header_t);
    len = header.fbox_len - sizeof(fbox_header_t);

    if ((nbytes = fread(buffer, 1, len, fd)) != len) {
        log_error("reading fbox failed exp=%d, nbytes=%d", len, nbytes);
        goto out;
    }

#ifdef UCAFS_SGX
    ecall_crypto_filebox(global_eid, &ret, &header, buffer, UC_DECRYPT);
    if (ret) {
        log_error("ecall_crypto_filebox %d", ret);
        goto out;
    }
#endif

    obj = (uc_filebox_t *)malloc(sizeof(uc_filebox_t));
    if (obj == NULL) {
        log_error("allocating dirnode object failed");
        goto out;
    }

    obj->fbox_path = sdsdup(filepath);
    obj->fbox = fbox;

    ret = 0;
out:
    fclose(fd);

    if (ret && fbox) {
        free(fbox);
    }

    if (ret && obj) {
        free(obj);
    }

    return obj;
}

uc_filebox_t *
filebox_from_file(const sds filepath)
{
    return filebox_from_file2(filepath, 0);
}

bool
filebox_write(uc_filebox_t * filebox, const char * fpath)
{
    int error;
    bool ret = false;
    FILE * fd;
    uc_fbox_t * fbox1 = NULL;
    size_t len = sizeof(fbox_header_t) + filebox->fbox->fbox_len;

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "file not found: %s", fpath);
        return false;
    }

    // copy in a seperate buffer here
    fbox1 = (uc_fbox_t *)calloc(1, len);
    if (fbox1 == NULL) {
        log_fatal("allocation error");
        return false;
    }

    memcpy(fbox1, filebox->fbox, len);

#ifdef UCAFS_SGX
    ecall_crypto_filebox(global_eid, &error, (fbox_header_t *)fbox1,
                         (void *)&fbox1->chunks, UC_ENCRYPT);
    if (error) {
        log_error("ecall_crypto_filebox %d", ret);
        goto out;
    }
#endif

    if (fwrite(fbox1, len, 1, fd) != 1) {
        slog(0, SLOG_ERROR, "filebox write failed");
        goto out;
    }

    ret = true;
out:
    fclose(fd);
    return ret;
}

bool
filebox_flush(uc_filebox_t * fb)
{
    return fb->fbox_path ? filebox_write(fb, fb->fbox_path) : false;
}

int
filebox_decr_link_count(uc_filebox_t * fb)
{
    return --fb->fbox->link_count;
}

int
filebox_incr_link_count(uc_filebox_t * fb)
{
    return ++fb->fbox->link_count;
}
