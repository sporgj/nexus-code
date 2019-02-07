#pragma once

#define NEXUS_NAME_MAX  256
#define NEXUS_PATH_MAX  1024

typedef enum {
    NEXUS_ENCRYPT,
    NEXUS_DECRYPT
} nexus_crypto_mode_t;


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

struct nexus_fs_lookup {
    struct nexus_uuid   uuid;

    nexus_dirent_type_t type;
};
