
/* Responsible for verifying the returned file versions */

#include <nexus_hashtable.h>
#include "internal.h"

#define HASHTABLE_SIZE 127

struct stash_verifier * stashv;

struct stash_verifier {
    struct nexus_hashtable * stash_table;

    size_t table_size;
};

//struct object_stash {
//    struct nexus_uuid uuid;
//
//    uint32_t version;
//
//};

/* 
 * Initialized the stash verifier, loads the stash file
 * of the volume from untrusted memory
 */
int
stashv_init(void *u_ptr) {

    if (u_ptr == NULL) {
        //create stash file for the volume if it does not exist
        stashv = nexus_malloc(sizeof (struct stash_verifier));

        stash_verifier->stash_table = nexus_create_htable(HASHTABLE_SIZE,
                __uuid_hasher,
                __uuid_equals);

        if (stash_verifier->stash_table == NULL) {
            nexus_free(stashv);
            log_error("nexus_create_htable FAILED\n");
            return -1;
        }
    } else {
        //load stash table TODO
    }
    return 0;
}

/* 
 * Adds a new UUID to the stash file
 * and initializes its version to 0
 */
int
stashv_add(struct nexus_uuid *uuid) {

    nexus_htable_insert(stashv->stash_table, uuid->raw, (uintptr_t) 0);
    return 0;
}

/* 
 * Verifies the returned version of the
 * file with the last seen version and if
 * the returned version if less than the seen
 * version update the stash file
 */
int
stashv_check_update(struct nexus_uuid *uuid, uint32_t version) {

    uint32_t seen_version = nexus_htable_search(stashv->stash_table, uuid->raw);
    if (seen_version < version) {
        nexus_htable_insert(stashv->stash_table, uuid->raw, version);
        //table.update(uuid, version);
        stashv_flush();
        return 0;
    } else if (seen_version == version) {
        return 0;
    }
    return -1;
}

/* 
 * Deletes an existing UUID from
 * the stash file
 */
int
stashv_delete(struct nexus_uuid *uuid) {

    //What is free key?
    nexus_htable_remove(stashv->stash_table, uuid->raw, 1);
    //table.remove(uuid);
    return 0;
}

/* 
 * Flushes the current state of the table
 * to stash file
 */
int
stashv_flush() {

    //serialize_table(table);
    return 0;
}

/* 
 * Exit 
 */
int
stashv_exit() {

    nexus_free_htable(stashv->stash_table, 0, 0);
    nexus_free(stashv);
    return 0;
}
//uint32_t
//get_version(uint32_t *uuid) {
//
//    char *token, *version;
//
//    char *search = ";";
//
//    static const char filename[] = "/tmp/file.txt";
//    FILE *file = fopen(filename, "r");
//    if (file != NULL) {
//        char line [ 128 ];
//        while (fgets(line, sizeof line, file) != NULL) {
//            token = strtok(line, search);
//            if (token == uuid) {
//                version = strtok(NULL, search);
//                break;
//            }
//        }
//        fclose(file);
//    }
//    return *(uint32_t *) & version;
//}






//void
//update_version(char *uuid, int version) {
//    
//}
//
//struct object_stash {
//};
//
//uint8_t *
//get_supernode_mac(struct nexus_metadata * key_encryption_key, struct nexus_key * secret_key) {
//
//}
//
//store_updated_version(UUID updated_object, int version) {
//    //Load the stash file based on volume
//    File stash_file = loadfile(vol_info);
//
//    // Find the UUID that needs to be changed
//    UUID modified_uuid = search_file(updated_object);
//
//    //Update the version
//
//    //Write the file back
//    saveFile();
//}

