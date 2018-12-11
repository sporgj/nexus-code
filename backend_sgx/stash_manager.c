#include "internal.h"

#include <nexus_mac.h>
#include <nexus_hashtable.h>
#include <nexus_file_handle.h>
#include <nexus_raw_file.h>


#define UUIDVERSION_FOLDER_NAME     "stashes"



struct __uuid_version_buf {
    struct nexus_uuid   uuid;

    struct nexus_mac    mac;

    uint32_t            version;
} __attribute__((packed));


struct __stash_verifier_hdr {
    uint32_t            entry_count;
} __attribute__((packed));



static struct nexus_hashtable           * stash_htable      = NULL;

static struct __stash_verifier_hdr        stash_header;

static struct nexus_file_handle         * stash_filehandle  = NULL;

static bool                               stash_is_dirty;



static struct __uuid_version_buf *
__get_version_buffer(struct nexus_uuid * uuid)
{
    return (struct __uuid_version_buf *)nexus_htable_search(stash_htable, (uintptr_t)uuid);
}

static struct __uuid_version_buf *
__del_version_buffer(struct nexus_uuid * uuid)
{
    struct __uuid_version_buf * version_buf = NULL;

    version_buf = (struct __uuid_version_buf *)nexus_htable_remove(stash_htable, (uintptr_t)uuid, 0);

    if (version_buf) {
        stash_header.entry_count -= 1;
        stash_is_dirty = true;
        return version_buf;
    }

    return NULL;
}

static void
__put_version_buffer(struct __uuid_version_buf * vbuf)
{
    if (nexus_htable_insert(stash_htable, (uintptr_t)&vbuf->uuid, (uintptr_t)vbuf) == 0) {
        abort();
    }

    stash_header.entry_count += 1;

    stash_is_dirty = true;
}



static int
__check_stash_folder()
{
    char * buffer = nexus_malloc(PATH_MAX);

    int ret = -1;


    // make the directory
    snprintf(buffer, PATH_MAX, "%s/%s", nexus_config.user_data_dir, UUIDVERSION_FOLDER_NAME);

    nexus_printf("Creating stashes folder... %s\n", buffer);

    ret = mkdir(buffer, 0770);

    if ((ret == -1) && (errno != EEXIST)) {
        log_error("could not create hashes directory (%s). ret=%d\n", buffer, ret);
        nexus_free(buffer);
        return -1;
    }

    nexus_free(buffer);

    return 0;
}


// uses the volume uuid to derive the path to the stash file
static char *
__derive_version_filepath(struct nexus_volume * volume)
{
    char * buffer = nexus_malloc(PATH_MAX);

    char * filename = nexus_uuid_to_alt64(&volume->vol_uuid);

    snprintf(buffer,
             PATH_MAX,
             "%s/%s/%s",
             nexus_config.user_data_dir,
             UUIDVERSION_FOLDER_NAME,
             filename);
    nexus_free(filename);

    return buffer;
}


int
__flush_version_buffer()
{
    return -1;
}


static int
__init_version_file(struct nexus_volume * volume)
{
    struct stat stat_buf;

    char * filepath = __derive_version_filepath(volume);


    if (stat(filepath, &stat_buf)) {
        nexus_printf("Initializing stash verifier file: %s\n", filepath);

        memset(&stash_header, 0, sizeof(struct __stash_verifier_hdr));

        if (nexus_write_raw_file(filepath, &stash_header, sizeof(struct __stash_verifier_hdr))) {
            log_error("could not write init version file (%s)\n", filepath);
            nexus_free(filepath);
            return -1;
        }
    }

    nexus_free(filepath);

    return 0;
}


static int
__parse_version_file() {
    struct __stash_verifier_hdr   tmp_header;

    int len    = 0;
    int nbytes = 0;


    if (lseek(stash_filehandle->fd, 0, SEEK_SET)) {
        log_error("rewind (%s)\n", stash_filehandle->filepath);
        return -1;
    }


    // read the header
    len    = sizeof(struct __stash_verifier_hdr);
    nbytes = write(stash_filehandle->fd, &tmp_header, len);

    if (nbytes != len) {
        log_error("read stash header FAILED. tried=%d, got=%d\n", len, nbytes);
        return -1;
    }


    len  = sizeof(struct __uuid_version_buf);


    // write the entries
    for (size_t i = 0; i < tmp_header.entry_count; i++) {
        struct __uuid_version_buf * uuid_version = nexus_malloc(sizeof(struct __uuid_version_buf));

        nbytes = read(stash_filehandle->fd, (uint8_t *)uuid_version, len);

        if (nbytes != len) {
            nexus_free(uuid_version);
            log_error("write stash file FAILED. tried=%d, got=%d\n", len, nbytes);
            return -1;
        }

        __put_version_buffer(uuid_version);
    }

    memcpy(&stash_header, &tmp_header, sizeof(struct __stash_verifier_hdr));

    return 0;
}


static int
__update_version_file() {
    struct nexus_hashtable_iter * iter         = NULL;

    struct __uuid_version_buf   * version_buf  = NULL;

    size_t len    = 0;
    size_t nbytes = 0;
    size_t buflen = 0;


    buflen = sizeof(struct __stash_verifier_hdr)
             + (stash_header.entry_count * sizeof(struct __uuid_version_buf));


    if (ftruncate(stash_filehandle->fd, buflen)) {
        log_error("ftruncate FAILED (file=%s, size=%zu)\n", stash_filehandle->filepath, buflen);
        return -1;
    }


    if (lseek(stash_filehandle->fd, 0, SEEK_SET)) {
        log_error("rewind (%s)\n", stash_filehandle->filepath);
        return -1;
    }


    // write the header
    len    = sizeof(struct __stash_verifier_hdr);
    nbytes = write(stash_filehandle->fd, &stash_header, len);

    if (nbytes != len) {
        log_error("write stash file FAILED. tried=%zu, got=%zu\n", len, nbytes);
        return -1;
    }


    len  = sizeof(struct __uuid_version_buf);


    iter = nexus_htable_create_iter(stash_htable);

    // write the entries
    do {
        version_buf = (struct __uuid_version_buf *)nexus_htable_get_iter_value(iter);

        nbytes = write(stash_filehandle->fd, (uint8_t *)version_buf, len);

        if (nbytes != len) {
            nexus_htable_free_iter(iter);
            log_error("write stash file FAILED. tried=%zu, got=%zu\n", len, nbytes);
            return -1;
        }
    } while (nexus_htable_iter_advance(iter));

    nexus_htable_free_iter(iter);


    if (fsync(stash_filehandle->fd)) {
        log_error("could not flush file (%s)\n", stash_filehandle->filepath);
        return -1;
    }

    return 0;
}


// opens and locks the version file
static int
__open_version_file(struct nexus_volume * volume)
{
    char * filepath = __derive_version_filepath(volume);

    stash_filehandle = nexus_file_handle_open(filepath, NEXUS_FRDWR); // locks the file

    if (stash_filehandle == NULL) {
        log_error("could not lock stash file (%s)\n", filepath);
        nexus_free(filepath);
        return -1;
    }

    nexus_free(filepath);

    return 0;
}


int
stash_manager_init(struct sgx_backend * backend)
{
    struct nexus_volume * volume = backend->volume;

    if (__check_stash_folder()) {
        log_error("__check_stash_folder FAILED\n");
        return -1;
    }

    if (__init_version_file(volume)) {
        log_error("__init_version_file FAILED\n");
        return -1;
    }

    if (__open_version_file(volume)) {
        log_error("__open_version_file FAILED\n");
        return -1;
    }

    if (__parse_version_file()) {
        log_error("__parse_version_file FAILED\n");
        return -1;
    }

    stash_htable = nexus_create_htable(256, uuid_hash_func, uuid_equal_func);

    return 0;
}


void
stash_manager_destroy()
{
    if (stash_filehandle) {
        nexus_file_handle_close(stash_filehandle);
        stash_filehandle = NULL;
    }

    if (stash_htable) {
        nexus_free_htable(stash_htable, 1, 0);
    }
}

int
stash_manager_store(struct nexus_uuid   * uuid,
                    struct nexus_mac    * mac,
                    uint32_t              version,
                    struct nexus_volume * volume)
{
    struct __uuid_version_buf  * uuidversion = __get_version_buffer(uuid);

    if (uuidversion == NULL) {
        uuidversion = nexus_malloc(sizeof(struct __uuid_version_buf));

        nexus_uuid_copy(uuid, &uuidversion->uuid);

        __put_version_buffer(uuidversion);

        return -1;
    }

    if (uuidversion->version > version) {
        uuidversion->version = version;

        nexus_mac_copy(mac, &uuidversion->mac);

        stash_is_dirty = true;

        __update_version_file();
    }

    return 0;
}

int
stash_manager_fetch(struct nexus_uuid   * uuid,
                    struct nexus_mac    * mac,
                    uint32_t            * version,
                    struct nexus_volume * volume)
{
    struct __uuid_version_buf * uuidversion = __get_version_buffer(uuid);

    if (uuidversion == NULL) {
        return -1;
    }

    *version = uuidversion->version;

    nexus_mac_copy(&uuidversion->mac, mac);

    return 0;
}


int
stash_manager_delete(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct __uuid_version_buf  * uuidversion = __del_version_buffer(uuid);

    if (uuidversion == NULL) {
        // XXX: should we revise this?
        return 0;
    }


    stash_is_dirty = true;

    nexus_free(uuidversion);

    return 0;
}
