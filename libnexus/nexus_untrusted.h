#pragma once



#if 0


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

// nexus_encode.c
extern size_t global_encoded_str_size;

void
compute_encoded_str_size();

struct nx_dentry;

struct nx_volume_item {
    int                     metadata_dir_len;
    int                     datafile_dir_len;
    char *                  metadata_dir;
    char *                  datafile_dir;
    char *                  root_dirnode_fpath;

    struct supernode_header supernode_header;
    struct nx_dentry *      root_dentry;
    TAILQ_ENTRY(nx_volume_item) next_item;
};

extern TAILQ_HEAD(nx_volume_list, nx_volume_item) * nx_volume_head;

// represents cached dirnode/filebox
typedef enum { NEXUS_DIRNODE, NEXUS_FILEBOX } nx_inode_type_t;

struct nx_inode {
    bool                    is_root_dirnode;
    nx_inode_type_t         type;
    char *                  fpath;
    struct nx_volume_item * volume;

    union {
        struct dirnode * dirnode;
        struct filebox * filebox;
    };
};

struct nx_dentry {
    char *                  name;
    size_t                  name_len;
    struct uuid             uuid;
    struct nx_dentry *      parent;

    struct nx_volume_item * volume;
    struct nx_inode *       inode;

    TAILQ_ENTRY(nx_dentry) next_item;
    TAILQ_HEAD(nx_dentry_list, nx_dentry) children;
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

struct nx_dentry *
nexus_vfs_lookup(const char * path);

struct nx_inode *
vfs_get_inode(const char * path);

int
vfs_create_inode(struct nx_inode * parent_inode,
                 struct uuid *     uuid,
                 nx_inode_type_t   type);

struct nx_inode *
vfs_read_inode(struct nx_dentry * dentry, struct path_builder * builder);

int
vfs_put_inode(struct nx_inode * inode);

int
vfs_flush_dirnode(struct nx_inode * inode, struct dirnode * dirnode);

void
vfs_refresh_inode(struct nx_inode * inode);

int
nexus_vfs_add_volume(struct supernode_header * supernode_header,
                     const char *              metadata_dir,
                     const char *              data_dir);

/* nexus_dentry.c */
struct nx_dentry *
nexus_dentry_lookup(struct nx_dentry * root_dentry, char * relpath);

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


#endif
