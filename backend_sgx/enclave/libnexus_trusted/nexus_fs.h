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

struct nexus_stat {
    // TODO
};
