/**
 * handles calls to the root hash
 *
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */

#include "internal.h"

#include <nexus_raw_file.h>


#define HASHTREE_FOLDER_NAME        "roothashes"


// for now we will just store the latest

struct __root_hash_buf {
    struct nexus_mac  root_mac;

    uint32_t          root_version;
} __attribute__((packed));


static struct __root_hash_buf   _roothash_buffer;


static int
__check_hashtree_folder()
{
    char * buffer = nexus_malloc(PATH_MAX);

    int ret = -1;


    // make the directory
    snprintf(buffer, PATH_MAX, "%s/%s", nexus_config.user_data_dir, HASHTREE_FOLDER_NAME);

    log_debug("Creating hastree folder... %s\n", buffer);

    ret = mkdir(buffer, 0770);

    if ((ret == -1) && (errno != EEXIST)) {
        log_error("could not create hashes directory (%s). ret=%d\n", buffer, ret);
        nexus_free(buffer);
        return -1;
    }

    nexus_free(buffer);

    return 0;
}

static char *
__get_hashtree_filepath(struct nexus_volume * volume)
{
    char * buffer = nexus_malloc(PATH_MAX);

    char * filename = NULL;

    // now touch the file
    filename = nexus_uuid_to_alt64(&volume->vol_uuid);
    snprintf(buffer, PATH_MAX, "%s/roothashes/%s", nexus_config.user_data_dir, filename);
    nexus_free(filename);

    return buffer;
}


static int
__init_hashtree_file(struct nexus_volume * volume)
{
    struct stat stat_buf;

    char * filepath = __get_hashtree_filepath(volume);


    if (stat(filepath, &stat_buf)) {
        // then we are creating the structure and writing it
        memset(&_roothash_buffer, 0, sizeof(struct __root_hash_buf));

        if (nexus_write_raw_file(filepath, &_roothash_buffer, sizeof(struct __root_hash_buf))) {
            nexus_free(filepath);
            return -1;
        }
    }

    nexus_free(filepath);

    return 0;
}

static int
__read_hashtree_file(struct nexus_volume * volume)
{
    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    char * filepath = __get_hashtree_filepath(volume);


    if (nexus_read_raw_file(filepath, &buffer, &buflen)) {
        log_error("could not read hashtree file (%s)\n", filepath);
        nexus_free(filepath);
        return -1;
    }

    if (buflen != sizeof(struct __root_hash_buf)) {
        log_error("incorrect size in root hash file (%s). expected=%zu, found=%zu\n",
                  filepath,
                  sizeof(struct __root_hash_buf),
                  buflen);
        nexus_free(filepath);
        return -1;
    }

    memcpy(&_roothash_buffer, buffer, sizeof(struct __root_hash_buf));

    nexus_free(filepath);

    return 0;
}

static int
__update_hashtree_file(struct nexus_volume * volume)
{
    uint8_t * buffer = (uint8_t *)&_roothash_buffer;
    size_t    buflen = sizeof(struct __root_hash_buf);

    char * filepath = __get_hashtree_filepath(volume);


    if (nexus_write_raw_file(filepath, buffer, buflen)) {
        log_error("could not write hashtree file (%s)\n", filepath);
        nexus_free(filepath);
        return -1;
    }

    nexus_free(filepath);

    return 0;
}


int
hashtree_manager_init(struct sgx_backend * backend)
{
    struct nexus_volume * volume = backend->volume;

    if (__check_hashtree_folder()) {
        log_error("could not confirm hashtree folder\n");
        return -1;
    }

    if (__init_hashtree_file(volume)) {
        log_error("could not initialize hashtree\n");
        return -1;
    }

    if (__read_hashtree_file(volume)) {
        log_error("could not read hashtree file\n");
        return -1;
    }

    return 0;
}

void
hashtree_manager_destroy(struct sgx_backend * backend)
{

}


int
hashtree_manager_update(uint32_t version, struct nexus_mac * mac, struct nexus_volume * volume)
{
    _roothash_buffer.root_version = version;

    nexus_mac_copy(mac, &_roothash_buffer.root_mac);

    return __update_hashtree_file(volume);
}

int
hashtree_manager_fetch(uint32_t * version, struct nexus_mac * mac, struct nexus_volume * volume)
{
    if (__read_hashtree_file(volume)) {
        log_error("could not read hashtree file\n");
        return -1;
    }

    *version = _roothash_buffer.root_version;

    nexus_mac_copy(&_roothash_buffer.root_mac, mac);

    return 0;
}
