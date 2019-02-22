/**
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/stat.h>

#include <linux/limits.h>

#include "nexus_uuid.h"

struct nexus_volume;

#define NEXUS_NAME_MAX  256
#define NEXUS_PATH_MAX  1024


// this will be the flags to create metadata/data files
#define NEXUS_POSIX_OPEN_MODE (S_IRUSR | S_IWUSR | \
                               S_IRGRP | S_IWGRP | \
                               S_IROTH | S_IWOTH)

#define NEXUS_POSIX_EXEC_MODE (S_IXUSR | S_IXGRP | S_IXOTH)


typedef enum {
    NEXUS_REG = 1,  /* regular file */
    NEXUS_DIR = 2,  /* directory    */
    NEXUS_LNK = 3   /* symlink      */
} nexus_dirent_type_t;


typedef enum {
    NEXUS_FREAD          = 0x00000001,
    NEXUS_FWRITE         = 0x00000002,
    NEXUS_FRDWR          = NEXUS_FREAD | NEXUS_FWRITE,

    NEXUS_FCREATE        = 0x00000004,
    NEXUS_FDELETE        = 0x00000008,

    NEXUS_IO_FNODE       = 0x00000010,
    NEXUS_IO_FCRYPTO     = 0x00000020,
} nexus_io_flags_t;

static inline bool nexus_io_in_lock_mode(nexus_io_flags_t flags) {
    return ((flags & (NEXUS_FWRITE | NEXUS_FCREATE | NEXUS_IO_FCRYPTO)) != 0);
}


typedef enum {
    NEXUS_STAT_LINK      = 0x0001, // lstat
    NEXUS_STAT_FILE      = 0x0002 // fstat
} nexus_stat_flags_t;


struct nexus_dirent {
    char                name[NEXUS_NAME_MAX];
    struct nexus_uuid   uuid;
    nexus_dirent_type_t type;
};

struct nexus_stat {
    /* data stored inside the actual metadata */
    size_t              link_count;  // number of hardlinks

    union {
        size_t          filesize;
        size_t          filecount;
    };

    nexus_dirent_type_t type;
    struct nexus_uuid   uuid;

    /* data stored inside the dirnode directory entry */
    nexus_dirent_type_t link_type;
    size_t              link_size;
    struct nexus_uuid   link_uuid;
};


// this will be implemented by the backend
struct nexus_file_xfer;


struct nexus_fs_lookup {
    struct nexus_uuid   uuid;

    nexus_dirent_type_t type;
};

// this structure will hold stat data
struct nexus_fs_attr {
    struct nexus_stat  stat_info;

    struct stat        posix_stat;
};



static inline mode_t
nexus_fs_sys_mode_from_type(nexus_dirent_type_t type)
{
    if (type == NEXUS_REG) {
        return S_IFREG;
    } else if (type == NEXUS_DIR) {
        return S_IFDIR;
    }

    return S_IFLNK;
}



/**
 * Creates a new file/dir
 * @param parent
 */
int
nexus_fs_create(struct nexus_volume  * volume,
                char                 * parent_dir,
                char                 * plain_name,
                nexus_dirent_type_t    type,
                struct nexus_uuid    * uuid);

int
nexus_fs_remove(struct nexus_volume     * volume,
                char                    * dirpath,
                char                    * plain_name,
                struct nexus_fs_lookup  * lookup_info,
                bool                    * should_remove);

int
nexus_fs_lookup(struct nexus_volume    * volume,
                char                   * parent_dir,
                char                   * plain_name,
                struct nexus_fs_lookup * lookup_info);


int
nexus_fs_stat(struct nexus_volume  * volume,
              char                 * path,
              nexus_stat_flags_t     stat_flags,
              struct nexus_stat    * nexus_stat);

int
nexus_fs_filldir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 char                 * nexus_name,
                 char                ** plain_name);

int
nexus_fs_readdir(struct nexus_volume  * volume,
                 char                 * dirpath,
                 struct nexus_dirent  * dirent_buffer_array,
                 size_t                 dirent_buffer_count,
                 size_t                 offset,
                 size_t               * result_count,
                 size_t               * directory_size);

int
nexus_fs_symlink(struct nexus_volume * volume,
                 char                * dirpath,
                 char                * link_name,
                 char                * target_path,
                 struct nexus_stat   * stat_info);

int
nexus_fs_readlink(struct nexus_volume * volume,
                  char                * dirpath,
                  char                * linkname,
                  char               ** target_path);

int
nexus_fs_hardlink(struct nexus_volume * volume,
                  char                * link_dirpath,
                  char                * link_name,
                  char                * target_dirpath,
                  char                * target_name,
                  struct nexus_uuid   * uuid);

int
nexus_fs_rename(struct nexus_volume     * volume,
                char                    * from_dirpath,
                char                    * oldname,
                char                    * to_dirpath,
                char                    * newname,
                struct nexus_uuid       * entry_uuid,
                struct nexus_fs_lookup  * overriden_entry,
                bool                    * should_remove);

int
nexus_fs_truncate(struct nexus_volume * volume,
                  char                * filepath,
                  size_t                size,
                  struct nexus_stat   * stat);

// this contains the file interface for performing crypto

/**
 * Starts the process for file encryption
 * @param volume
 * @param filepath
 * @param filesize
 * @return @struct nexus_file_crypto
 */
struct nexus_file_crypto *
nexus_fs_file_encrypt_start(struct nexus_volume * volume, char * filepath, size_t filesize);

/**
 * Same as @nexus_fs_file_encrypt_start, but decryption instead
 */
struct nexus_file_crypto *
nexus_fs_file_decrypt_start(struct nexus_volume * volume, char * filepath);

/**
 * Performs a seek to the offset.
 * When encrypting, this might return false if a chunk is not completed
 * @param file_crypto
 * @param offset
 * @return -1 on failure
 */
int
nexus_fs_file_crypto_seek(struct nexus_volume * volume, struct nexus_file_crypto * file_crypto, size_t offset);

/**
 * Used for encrypting data. Note that the offset is shifted by the amount
 * of processed data.
 *
 * Returns -1 on FAILURE
 */
int
nexus_fs_file_crypto_encrypt(struct nexus_volume      * volume,
                             struct nexus_file_crypto * file_crypto,
                             const uint8_t            * plaintext_input,
                             uint8_t                  * encrypted_input,
                             size_t                     size,
                             size_t                   * processed_bytes);

// @see nexus_fs_file_crypto_encrypt
int
nexus_fs_file_crypto_decrypt(struct nexus_volume      * volume,
                             struct nexus_file_crypto * file_crypto,
                             uint8_t                  * decrypted_output,
                             size_t                     size,
                             size_t                   * processed_bytes);
/**
 * Terminates the crypto process and writes out the filenode metadata.
 */
int
nexus_fs_file_crypto_finish(struct nexus_volume * volume, struct nexus_file_crypto * file_crypto);
