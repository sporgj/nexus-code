#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uc_sgx.h"
#include "uc_supernode.h"

#include "third/log.h"
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
    SIMPLEQ_INIT(&super->users_list);

    return super;
}

static int
_supernode_unwrap(supernode_t * super)
{
    int ret = -1, i = 0, len;
    snode_user_t * curr_user;
    snode_user_entry_t * user_entry;
    SIMPLEQ_INIT(&super->users_list);

    curr_user = (snode_user_t *)super->users_buffer;
    while (i < super->user_count) {
        /* create a new entry */
        user_entry = (snode_user_entry_t *)malloc(sizeof(snode_user_entry_t));
        if (user_entry == NULL) {
            log_fatal("allocation failed");
            goto out;
        }

        len = sizeof(snode_user_t) + curr_user->len;
        memcpy(user_entry, curr_user, len);

        /* add it to the list and move on to the next entry */
        SIMPLEQ_INSERT_TAIL(&super->users_list, user_entry, next_user);

        curr_user = (snode_user_t *)(((uint8_t *)curr_user) + len);
        i++;
    }
    
    super->is_wrapped = false;
    free(super->users_buffer);
    super->users_buffer = NULL;

    ret = 0;
out:
    return ret;
}

static int
_supernode_wrap(supernode_t * super)
{
    int ret = -1, len;
    snode_user_entry_t * curr;

    uint8_t * buffer = (uint8_t *)malloc(super->users_buflen), *buf = buffer;
    if (buffer == NULL) {
        log_fatal("allocation failed");
        goto out;
    }

    SIMPLEQ_FOREACH(curr, &super->users_list, next_user)
    {
        len  = sizeof(snode_user_t) + curr->len;
        memcpy(buf, curr, len);

        buf += len;
    }

    // XXX this should never happen but, lets just be safe
    if (super->users_buffer) {
        free(super->users_buffer);
    }

    super->users_buffer = buffer;
    super->is_wrapped = true;
    ret = 0;
out:
    return ret;
}

supernode_t *
supernode_from_file(const char * path)
{
    int err = -1, ret;
    supernode_t * super = NULL;
    uint8_t * buffer = NULL;
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

    nbytes = fread(super, sizeof(supernode_header_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "superblock format error: %s", path);
        goto out;
    }

    buffer = (uint8_t *)malloc(super->users_buflen);
    if (buffer == NULL) {
        log_error("allocation error");
        goto out;
    }

    nbytes = fread(buffer, 1, super->users_buflen, fd);
    if (nbytes != super->users_buflen) {
        log_error("read error supernode (%s). exp=%u, act=%zu", path,
                  super->users_buflen, nbytes);
        goto out;
    }

    super->users_buffer = buffer;
    err = 0;
out:
    fclose(fd);

    if (err) {
        free(super);
        super = NULL;
    }

    if (err && buffer) {
        free(buffer);
    }

    return super;
}

int
supernode_unwrap(supernode_t * super)
{
    int ret = -1;

#ifdef UCAFS_SGX
    ecall_supernode_crypto(global_eid, &ret, super, CRYPTO_UNSEAL);
    if (ret) {
        log_error("enclave operation failed\n");
        goto out;
    }
#endif

    /* now lets parse the users buffer into a linked list */
    if (_supernode_wrap(super)) {
        goto out;
    }

    ret = 0;
out:
    return ret;
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
    ecall_supernode_crypto(global_eid, &ret, super, CRYPTO_SEAL);
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

int
supernode_add(supernode_t * super,
              const char * username,
              const uint8_t hash[CONFIG_SHA256_BUFLEN])
{
    int ret = -1, len;
    struct snode_user_entry * curr;

    /* iterate the list and check if the same public key/password exists */
    SIMPLEQ_FOREACH(curr, &super->users_list, next_user)
    {
        if (strncmp(curr->username, username, curr->len) == 0) {
            slog(0, SLOG_ERROR, "user '%s' already exists in superblock",
                 username);
            goto out;
        }

        if (memcmp(curr->pubkey_hash, hash, CONFIG_SHA256_BUFLEN) == 0) {
            slog(0, SLOG_ERROR, "user '%s', already has public key",
                 curr->username);
            goto out;
        }
    }

    /* add it to the list and call it a day */
    len = strlen(username);
    curr = (struct snode_user_entry *)malloc(sizeof(struct snode_user_entry)
                                             + len);
    if (curr == NULL) {
        slog(0, SLOG_ERROR, "memory allocation failed");
        goto out;
    }

    curr->len = len;
    memcpy(curr->username, username, len);
    memcpy(curr->pubkey_hash, hash, CONFIG_SHA256_BUFLEN);

    SIMPLEQ_INSERT_TAIL(&super->users_list, curr, next_user);
    super->user_count++;
    super->users_buflen += sizeof(snode_user_t) + curr->len;

    ret = 0;
out:
    return ret;
}

/**
 * removes an entry in the list of users. It stops iterating on find the first
 * matching name/pubkey
 */
int
supernode_rm(supernode_t * super,
             const char * username,
             const uint8_t hash[CONFIG_SHA256_BUFLEN])
{
    int ret = -1, len;
    struct snode_user_entry *curr, *prev = NULL;

    /* iterate the list and check if the same public key/password exists */
    SIMPLEQ_FOREACH(curr, &super->users_list, next_user)
    {
        if (strncmp(curr->username, username, curr->len) == 0) {
            goto remove;
        }

        if (memcmp(curr->pubkey_hash, hash, CONFIG_SHA256_BUFLEN) == 0) {
            goto remove;
        }

        prev = curr;
    }

    goto out;
remove:
    super->user_count--;
    super->users_buflen -= sizeof(snode_user_t) + curr->len;

    SIMPLEQ_REMOVE_AFTER(&super->users_list, prev, next_user);
    free(curr);
out:
    return 0;
}
