#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uc_sgx.h"
#include "uc_supernode.h"

#include "third/slog.h"

supernode_t *
supernode_new()
{
    supernode_t * super = (supernode_t *)calloc(1, sizeof(supernode_t));
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

supernode_t *
supernode_from_file(const char * path)
{
    int err = -1;
    supernode_t * super = NULL;
    FILE * fd;
    size_t nbytes;

    fd = fopen(path, "rb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "could not open %s", path);
        return NULL;
    }

    super = (supernode_t *)malloc(sizeof(supernode_t));
    if (super == NULL) {
        // TODO die here
        goto out;
    }

    nbytes = fread(super, sizeof(supernode_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "superblock format error: %s", path);
        goto out;
    }

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
supernode_write(supernode_t * super, const char * path)
{
    bool err = false;
    int ret = -1;
    FILE * fd;
    size_t nbytes;

    fd = fopen(path, "wb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "could not open %s", path);
        return false;
    }

#ifdef UCAFS_SGX
    // seal info here
    ecall_seal_supernode(global_eid, &ret, super);
    if (ret) {
        slog(0, SLOG_ERROR, "sealing supernode failed");
        goto out;
    }
#endif

    nbytes = fwrite(super, sizeof(supernode_t), 1, fd);
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
supernode_free(supernode_t * super)
{
    free(super);
}
