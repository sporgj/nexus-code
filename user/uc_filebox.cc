#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include "third/slog.h"
}

#include "fbox.pb.h"

#include "uc_filebox.h"
#include "uc_types.h"

class fbox;

struct filebox {
    fbox_header_t header;
    fbox * protobuf;
    sds fbox_path;
};

uc_filebox_t *
filebox_new()
{
    uc_filebox_t * fb = (uc_filebox_t *)malloc(sizeof(uc_filebox_t));
    if (fb == NULL) {
        return NULL;
    }

    memset(&fb->header, 0, sizeof(fbox_header_t));
    fb->protobuf = new fbox();
    fb->fbox_path = NULL;

    // TODO initialize default segment;
    uuid_generate_time_safe(fb->header.uuid);
}

void
filebox_free(uc_filebox_t * fb)
{
    delete fb->protobuf;

    if (fb->fbox_path) {
        sdsfree(fb->fbox_path);
    }

    free(fb);
}

uc_filebox_t *
filebox_from_file(const sds filepath)
{
    uc_filebox_t * obj = NULL;
    fbox * proto = nullptr;
    fbox_header_t header;
    uint8_t * buffer = NULL;
    FILE * fd;
    size_t nbytes;
    int error = -1;

    fd = fopen(filepath, "rb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "filebox - could not open: %s", filepath);
        return NULL;
    }

    /* read the header from the file */
    nbytes = fread(&header, sizeof(fbox_header_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "filebox - could not read header: %s (nbytes=%u)",
             filepath, nbytes);
        goto out;
    }

    proto = new fbox();
    if (header.protolen) {
        if ((buffer = (uint8_t *)malloc(header.protolen)) == NULL) {
            slog(0, SLOG_ERROR, "filebox - allocation for dnode failed");
            goto out;
        }

        if ((nbytes = fread(buffer, 1, header.protolen, fd))
            != header.protolen) {
            slog(0, SLOG_ERROR, "filebox - reading protobuf failed:"
                                "expected=%u, actual=%u",
                 header.protolen, nbytes);
            goto out;
        }

        if (!proto->ParseFromArray(buffer, header.protolen)) {
            slog(0, SLOG_ERROR, "filebox - parsing protobuf failed: %s",
                 filepath);
            goto out;
        }
    }

    obj = (uc_filebox_t *)malloc(sizeof(uc_filebox_t));
    if (obj == NULL) {
        slog(0, SLOG_ERROR, "filebox - allocating dirnode object failed");
        goto out;
    }

    obj->fbox_path = sdsdup(filepath);
    obj->protobuf = proto;
    memcpy(&obj->header, &header, sizeof(fbox_header_t));
    error = 0;
out:
    if (error) {
        // free the object
        delete proto;
    }

    if (buffer) {
        free(buffer);
    }

    fclose(fd);
    return obj;
}

bool
filebox_write(uc_filebox_t * fb, const char * fpath)
{
    bool ret = false;
    uint8_t * buffer = NULL;
    size_t len = CRYPTO_CEIL_TO_BLKSIZE(fb->protobuf->ByteSize());
    FILE * fd;

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "filebox - file not found: %s", fpath);
        return false;
    }

    if ((buffer = (uint8_t *)malloc(len)) == NULL) {
        slog(0, SLOG_ERROR, "filebox - alloc error for write buffer");
        goto out;
    }

    if (!fb->protobuf->SerializeToArray(buffer, len)) {
        slog(0, SLOG_ERROR, "filebox - serialization failed");
        goto out;
    }

    /* GetCachedSize returns the size computed from ByteSize() */
    fb->header.protolen = fb->protobuf->GetCachedSize();

    fwrite(&fb->header, sizeof(fbox_header_t), 1, fd);
    fwrite(buffer, fb->header.protolen, 1, fd);

    ret = true;
out:
    fclose(fd);
    if (buffer) {
        free(buffer);
    }

    return ret;
}

bool
filebox_flush(uc_filebox_t * fb)
{
    return fb->fbox_path ? filebox_write(fb, fb->fbox_path) : false;
}

crypto_context_t *
filebox_get_crypto(uc_filebox_t * fb, size_t chunk_id)
{
    return (crypto_context_t *)calloc(1, sizeof(crypto_context_t));
}

