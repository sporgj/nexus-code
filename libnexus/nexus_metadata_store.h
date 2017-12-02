#pragma once

#include <time.h>

struct nexus_dentry;
struct neuxs_metadata_operations;

struct nexus_volume {
    char * metadata_dirpath;
    char * datafolder_dirpath;

    struct volumekey * volumekey;

    struct supernode *    supernode;
    struct nexus_dentry * root_dentry;
};

typedef enum { DIRNODE, FILENODE } nexus_metadata_type_t;

struct nexus_metadata {
    bool is_dirty;
    bool is_root_dirnode;

    clock_t timestamp;

    nexus_metadata_type_t type;

    char *                fpath;
    struct nexus_volume * volume;

    union {
        void *           buffer;
        struct dirnode * dirnode;
        struct filebox * filebox;
    };
};

/**
 * Allows the backend to lookup for a file in a dirnode. Used for the dentry
 * cache
 * @param dirnode
 * @param fname
 * @param uuid_dest where the uuid will be copied to
 * @param p_type destination type
 */
int
nexus_dirnode_lookup(struct dirnode *      dirnode,
                     char *                fname,
                     struct uuid *         uuid_dest,
                     nexus_fs_obj_type_t * p_type);

/**
 * Creates a new volume of the type
 * @param supernode
 * @param root_dirnode
 * @param metadata
 */
int
metadata_create_volume(struct supernode * supernode,
                       struct dirnode *   root_dirnode,
                       struct volumekey * volumekey,
                       const char *       metadata_dirpath,
                       const char *       volumekey_fpath);

/**
 * Mounts a volume. Will read the supernode from disk and fill
 * volume->supernode
 *
 * @param metadata_dirpath
 * @param filedata_dirpath
 * @return NULL
 */
struct nexus_volume *
metadata_mount_volume(const char * metadata_dirpath,
                      const char * filedata_dirpath,
                      const char * volumekey_fpath);

/**
 * Unmounts the volume from the metadata store
 * @param volume
 */
void
metadata_umount_volume(struct nexus_volume * volume);
