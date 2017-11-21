#pragma once

/**
 * defines all the functions used by the untrusted code
 */
#include <stdlib.h>

#include <sgx_urts.h>

#include "nexus.h"
#include "nexus_log.h"

#include "nexus_types.h"
#include "nexus_util.h"

#include "enclave/queue.h"

#include "nx_enclave_u.h"

struct nx_volume_item {
    struct supernode_header supernode_header;
    int                     metadata_dir_len;
    int                     datafile_dir_len;
    char *                  metadata_dir;
    char *                  datafile_dir;
    char *                  root_dirnode_fpath;
    TAILQ_ENTRY(nx_volume_item) next_item;
};

extern TAILQ_HEAD(nx_volume_list, nx_volume_item) * nx_volume_head;

// represents cached dirnode/filebox
typedef enum { NEXUS_DIRNODE, NEXUS_FILEBOX } nx_inode_type_t;

struct nx_inode {
    nx_inode_type_t type;
    char * fpath;
    union {
        struct dirnode * dirnode;
        struct filebox * filebox;
    };
};

extern sgx_enclave_id_t global_enclave_id;

/* nx_encode.c */
char *
metaname_bin2str(const struct uuid * uuid);

struct uuid *
metaname_str2bin(const char * str);

char *
filename_bin2str(const struct uuid * uuid);

struct uuid *
filename_str2bin(const char * str);


/* nexus_vfs.c */
int
nexus_vfs_init();

void
nexus_vfs_exit();

struct nx_inode *
nexus_get_inode(const char * path);

int
nexus_put_inode(struct nx_inode * inode);

int
nexus_flush_dirnode(struct nx_inode * inode, struct dirnode * dirnode);

int
nexus_vfs_add_volume(struct supernode_header * supernode_header,
                     const char *              metadata_dir,
                     const char *              data_dir);

/* nexus_volume.c */
int
nexus_create_volume(char               * publickey_fpath,
                    struct supernode  ** p_supernode,
                    struct dirnode    ** p_root_dirnode,
                    struct volumekey ** p_sealed_volumekey);
int
nexus_login_volume(const char *       publickey_fpath,
                   const char *       privatekey_fpath,
                   struct supernode * supernode,
                   struct volumekey * volumekey);

int
nexus_mount_volume(struct supernode * supernode,
                   struct volumekey * volumekey,
                   const char *       metadata_dir,
                   const char *       data_dir);
