#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nexus_hashtable.h>
#include <nexus_util.h>
#include <nexus_raw_file.h>
#include "internal.h"
#include <fcntl.h>
#include <nexus_json.h>

#define STASH_PATH "/home/henrique/.nexus/stashes/nexus_stash.bin"
#define STASH_PATH2 "/home/henrique/.nexus/stashes/nexus_stash2.bin"

struct stash_verifier {
    struct nexus_hashtable * stash_table;
    size_t table_size;
};

static struct stash_verifier * stash;
static nexus_json_obj_t stash_json = NEXUS_JSON_INVALID_OBJ;

int load_stash_file(char * path);
int write_initial_stash();
int update_stash_file(struct nexus_uuid *uuid, uint32_t * stash_version);

int
ocall_stash_init(struct nexus_uuid *uuid) {

    char * stash_path = STASH_PATH;

    int fd = open(STASH_PATH, O_WRONLY | O_CREAT | O_EXCL, 0666);

    if (fd == -1 && errno == EEXIST) {
        /* the file already exists */
        load_stash_file(stash_path);

    } else if (fd == -1) {
        /* report that some other error happened */
        log_error("Error when loading stash verifier file.\n");
    } else {
        /* File not created yet */
        int stash_size = sizeof (struct stash_verifier);
        stash = nexus_malloc(stash_size);

        stash->stash_table = nexus_create_htable(17, uuid_hash_func, uuid_equal_func);

        if (write_initial_stash() == -1) {
            return -1;
        }

        if (stash->stash_table == NULL) {
            nexus_free(stash);
            log_error("Stash hashtable FAILED\n");
            return -1;
        }
    }
    return 0;
}

/*
 * Returns a version from a stashed UUID loaded from the stash json file
 */
uint32_t *
ocall_stash_get(struct nexus_uuid *uuid) {

    //Copy the uuid to a unsecure memory region
    struct nexus_uuid *local_uuid = nexus_malloc(sizeof (struct nexus_uuid));
    memcpy(local_uuid, uuid, sizeof (struct nexus_uuid));

    uint32_t* stash_version = NULL;
    stash_version = nexus_htable_search(stash->stash_table, (uintptr_t) local_uuid);

    //Copy the copy results to a new place in unsecure memory. (A segfault will happen if not)
    uint32_t* external_adr = malloc(sizeof (uint32_t));
    memcpy(external_adr, stash_version, sizeof (uint32_t));

    //Freeing local uuid copy
    nexus_free(local_uuid);
    
    return external_adr;
}

/*
 * Updates the local stash hashtable and push the changes to json stash file in disk
 */
int
ocall_stash_put(struct nexus_uuid *uuid, uint32_t * fresh_version) {

    // Copy version to unsecure memory location
    uint32_t *local_fresh_version = nexus_malloc(sizeof (uint32_t));
    memcpy(local_fresh_version, fresh_version, sizeof (uint32_t));

    // Copy uuid to unsecure memory location
    struct nexus_uuid *local_uuid = nexus_malloc(sizeof (struct nexus_uuid));
    memcpy(local_uuid, uuid, sizeof (struct nexus_uuid));

    // Verifies if that file already has a version stashed
    uint32_t * stash_version = nexus_htable_search(stash->stash_table, (uintptr_t) local_uuid);

    //If NULL its a new file. Add it to the stash
    if (stash_version == NULL || *stash_version < *local_fresh_version) {
        nexus_htable_insert(stash->stash_table, (uintptr_t) local_uuid, (uintptr_t) local_fresh_version);
        
        // Saves the uuid to disk.
        update_stash_file(uuid,fresh_version);
        
        //Debug Sanity check (Will be removed)
        uint32_t * stash_version2 = nexus_htable_search(stash->stash_table, (uintptr_t) local_uuid);
        if (*stash_version2 < *local_fresh_version) {
        }

    } else {
        
        nexus_free(local_fresh_version);
        nexus_free(local_uuid);
        //Local stash version is older than requested
        return -1;
    }

    return 0;
}

int
load_stash_file(char * path) {
    stash_json = nexus_json_parse_file(path);

    if (stash_json == NEXUS_JSON_INVALID_OBJ) {
        log_error("Could not open file (%s)\n", path);
        goto err;
    }

    int idx = 0;
    nexus_json_obj_t child_json_node;
    stash = nexus_malloc(sizeof (struct stash_verifier));
    stash->stash_table = nexus_create_htable(20, uuid_hash_func, uuid_equal_func);
    struct nx_json * json_node;
    struct nexus_uuid * uuid_json;

    //Iterating over root json node childs
    while ((child_json_node = nexus_json_array_get_child_by_index(stash_json, idx)) != NEXUS_JSON_INVALID_OBJ) {
        json_node = (struct nx_json *) child_json_node;

        uuid_json = nexus_malloc(sizeof (struct nexus_uuid));

        //Rebuilding UUID from json string
        int i = 0;
        for (i = 0; i < NEXUS_UUID_SIZE; i++) {
            uuid_json->raw[i] = json_node->key[i];
        }

        nexus_htable_insert(stash->stash_table, (uintptr_t) uuid_json, (uintptr_t) & json_node->int_value);
        idx++;
    }

    return 0;

err:
    if (stash_json != NEXUS_JSON_INVALID_OBJ) {
        nexus_json_free(stash_json);
    }

    return -1;
}

/*
 * Creates and Writes an empty json based stash file for initialization.
 */
int
write_initial_stash() {
    char * path = STASH_PATH;
    int ret = 0;

    stash_json = nexus_json_new_obj("stash");

    //Sanity check contents
    nexus_json_add_u32(stash_json, "0611c129-b98a-4956-9755-a684bcbb15a0", 10);
    nexus_json_add_u32(stash_json, "f355cfda-0c60-495a-b8d9-adf973e21bb4", 12);


    char * root_json_str = nexus_json_serialize(stash_json);

    if (root_json_str == NULL) {
        log_error("Could not serialize root stash node!\n");
        goto err;
    }

    nexus_write_raw_file(path, root_json_str, strlen(root_json_str) + 1);

    if (ret == -1) {
        log_error("Could not store root stash node json file!\n");
        goto err;
    }

    nexus_json_free(stash_json);
    nexus_free(root_json_str);

    return 0;

err:

    if (root_json_str) nexus_free(root_json_str);

    if (stash_json != NEXUS_JSON_INVALID_OBJ) {
        nexus_json_free(stash_json);
    }

    return -1;
}


int
update_stash_file(struct nexus_uuid *uuid, uint32_t * stash_version) {
    
    char * path = STASH_PATH;
    int ret = 0;

    //uint8_t uuid_int[16] = uuid->raw;
    
    //Copy uuid to a char* pointed mem region
    
    char* uuid_char = nexus_uuid_to_alt64(uuid);  
    
//    char* uuid_char = nexus_malloc(16);
//    memcpy(uuid_char, uuid->raw, 16);
    
    nexus_json_add_u32(stash_json, uuid_char, *stash_version);
    
    char * root_json_str = nexus_json_serialize(stash_json);

    if (root_json_str == NULL) {
        log_error("Could not serialize root stash node!\n");
        goto err;
    }

    nexus_write_raw_file(path, root_json_str, strlen(root_json_str) + 1);

    if (ret == -1) {
        log_error("Could not store root stash node json file!\n");
        goto err;
    }

    nexus_json_free(stash_json);
    nexus_free(root_json_str);
    nexus_free(uuid_char);

    return 0;

err:

    if (root_json_str) nexus_free(root_json_str);

    if (stash_json != NEXUS_JSON_INVALID_OBJ) {
        nexus_json_free(stash_json);
    }

    return -1;
}

int
ocall_stash_exit() {
    nexus_free_htable(stash->stash_table, 1, 0);
    return 0;
}

int
ocall_stash_evict(struct nexus_uuid * uuid) {
    int * version = (int*) nexus_htable_remove(stash->stash_table, (uintptr_t) uuid, 0);
    nexus_free(version);
    
    return 1;
}

int
write_initial_stash2() {
    char * path = STASH_PATH;

    nexus_json_obj_t dir_json = NEXUS_JSON_INVALID_OBJ;
    nexus_json_obj_t child_json = NEXUS_JSON_INVALID_OBJ;

    char * my_uuid_alt64 = NULL;
    char * parent_uuid_alt64 = NULL;

    char * dir_str = NULL;

    int ret = 0;

    //my_uuid_alt64     = nexus_uuid_to_alt64(&(dirnode->my_uuid));  

    dir_json = nexus_json_new_obj("stash");
    child_json = nexus_json_new_obj("node_stash");

    int version = 30;

    //nexus_json_add_string(dir_json, "uuid",    my_uuid_alt64);
    nexus_json_add_u32(dir_json, "version", version);
    nexus_json_add_u32(child_json, "version2", 4);
    nexus_json_splice(dir_json, child_json);

    dir_str = nexus_json_serialize(dir_json);

    if (dir_str == NULL) {
        log_error("Could not serialize dirnode\n");
        goto err;
    }


    nexus_write_raw_file(path, dir_str, strlen(dir_str) + 1);

    //    ret = nexus_datastore_put_uuid(volume->metadata_store,
    //				   &(dirnode->my_uuid),
    //				   NULL,
    //				   (uint8_t *)dir_str,
    //				   strlen(dir_str) + 1);


    if (ret == -1) {
        log_error("Could not store dirnode\n");
        goto err;
    }

    nexus_json_free(dir_json);
    //nexus_free(my_uuid_alt64);

    nexus_free(dir_str);

    return 0;

err:

    if (my_uuid_alt64) nexus_free(my_uuid_alt64);
    if (parent_uuid_alt64) nexus_free(parent_uuid_alt64);
    if (dir_str) nexus_free(dir_str);

    if (dir_json != NEXUS_JSON_INVALID_OBJ) {
        nexus_json_free(dir_json);
    }
    return -1;
}
