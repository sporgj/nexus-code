#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include "third/slog.h"
}

#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_sgx.h"
#include "uc_types.h"
#include "uc_utils.h"
#include "uc_uspace.h"

struct filebox {
    uc_fbox_t * fbox;
    sds fbox_path;
};

uc_filebox_t *
filebox_new()
{
    uc_fbox_t * fbox;
    uc_filebox_t * filebox = (uc_filebox_t *)malloc(sizeof(uc_filebox_t));
    if (filebox == NULL) {
        slog(0, SLOG_FATAL, "allocation error");
        return NULL;
    }

    filebox->fbox_path = NULL;

    // instantiate a default fbox
    if ((fbox = (uc_fbox_t *)calloc(1, sizeof(uc_fbox_t))) == NULL) {
        slog(0, SLOG_FATAL, "allocating fbox failed");
        free(filebox);
        return NULL;
    }

    fbox->magic = UCAFS_FBOX_MAGIC;
    fbox->chunk_count = 1;
    fbox->chunk_size = UCAFS_CHUNK_SIZE;
    fbox->fbox_len = FBOX_DEFAULT_LEN;
    fbox->file_size = 0;
    fbox->link_count = 1;
    uuid_generate_time_safe(fbox->uuid);

    filebox->fbox = fbox;

    return filebox;
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

uc_filebox_t *
filebox_from_shadow_name2(const shadow_t * shdw_name, size_t hint)
{
    char * temp = metaname_bin2str(shdw_name);
    sds fbox_path = uc_get_dnode_path(temp);

    uc_filebox_t * fb = filebox_from_file2(fbox_path, hint);

    free(temp);
    sdsfree(fbox_path);
    return fb;
}

uc_filebox_t *
filebox_from_shadow_name(const shadow_t * shdw_name)
{
    return filebox_from_shadow_name2(shdw_name, 0);
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
    uc_fbox_header_t header;
    uc_fbox_t * fbox;
    int len, nbytes;
    uint8_t * buffer;
    FILE * fd;
    int ret = -1;

    fd = fopen(filepath, "rb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "could not open: %s", filepath);
        return NULL;
    }

    /* read the header from the file */
    nbytes = fread(&header, sizeof(uc_fbox_header_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "could not read header: %s (nbytes=%u)", filepath,
             nbytes);
        goto out;
    }

    /* now detect how much data to allocate */
    len = MAX(size_hint, header.fbox_len);
    if ((fbox = (uc_fbox_t *)malloc(header.fbox_len)) == NULL) {
        slog(0, SLOG_FATAL, "allocation failed. len=%u", header.fbox_len);
        goto out;
    }

    memcpy(fbox, &header, sizeof(uc_fbox_header_t));
    buffer = ((uint8_t *)fbox) + sizeof(uc_fbox_header_t);
    len -= sizeof(uc_fbox_header_t);

    if ((nbytes = fread(buffer, 1, len, fd)) != len) {
        slog(0, SLOG_ERROR, "reading fbox failed exp=%d, nbytes=%d", len,
             nbytes);
        goto out;
    }

    obj = (uc_filebox_t *)malloc(sizeof(uc_filebox_t));
    if (obj == NULL) {
        slog(0, SLOG_ERROR, "allocating dirnode object failed");
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
    bool ret = false;
    FILE * fd;

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "file not found: %s", fpath);
        return false;
    }

    // TODO add sgx sealing here

    if (fwrite(filebox->fbox, filebox->fbox->fbox_len, 1, fd) != 1) {
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
