#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uc_superblock.h"

#include "third/slog.h"

superblock_t *
superblock_new()
{
    superblock_t * super = (superblock_t *)malloc(sizeof(superblock_t));
    if (super == NULL) {
        // TODO die here
        return NULL;
    }

    uuid_generate_time_safe((uint8_t *)&super->root_dnode);

#ifdef UCAFS_SGX
// TODO call sgx crypto initializer here
#endif

    return super;
}

superblock_t *
superblock_from_file(char * path)
{
    int err = -1;
    superblock_t * super = NULL;
    FILE * fd;
    size_t nbytes;

    fd = fopen(path, "rb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "could not open %s", path);
        return NULL;
    }

    super = (superblock_t *)malloc(sizeof(superblock_t));
    if (super == NULL) {
        // TODO die here
        goto out;
    }

    nbytes = fread(super, sizeof(superblock_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "superblock format error: %s", path);
        goto out;
    }

#ifdef UCAFS_SGX
// verify the superblock object here
#endif

    err = 0;
out:
    fclose(fd);

    if (err) {
        free(super);
        super = NULL;
    }

    return super;
}

bool
superblock_flush(superblock_t * super, char * path)
{
    bool err = false;
    FILE * fd;
    size_t nbytes;

    fd = fopen(path, "rb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "could not open %s", path);
        return false;
    }

#ifdef UCAFS_SGX
// seal info here
#endif

    nbytes = fwrite(super, sizeof(superblock_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "writing superblock %s failed", path);
        goto out;
    }

    err = true;
out:
    fclose(fd);

    return err;
}

void
superblock_free(superblock_t * super)
{
    free(super);
}
