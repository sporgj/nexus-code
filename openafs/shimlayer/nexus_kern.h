#pragma once


#include <linux/dcache.h>

#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"




typedef enum {
    NEXUS_ANY  = 0,
    NEXUS_FILE = 1,
    NEXUS_DIR  = 2,
    NEXUS_LINK = 3
} nexus_fs_obj_type_t;


typedef enum {
    NEXUS_RET_OK    =  0,
    NEXUS_RET_ERROR = -1,
    NEXUS_RET_NOOP  = -2    // when it is not a nexus volume
} nexus_ret_t;




char * nexus_get_path_from_dentry(struct dentry * dentry);
char * nexus_get_path_from_vcache(struct vcache * vcache);




/* chunk size */
#define NEXUS_CHUNK_LOG 20
#define NEXUS_CHUNK_SIZE (1 << NEXUS_CHUNK_LOG)



static inline size_t
NEXUS_CHUNK_BASE(size_t offset)
{
    return ((offset < NEXUS_CHUNK_SIZE)
                ? 0
                : (((offset - NEXUS_CHUNK_SIZE) & ~(NEXUS_CHUNK_SIZE - 1))
                   + NEXUS_CHUNK_SIZE));
}

static inline size_t
NEXUS_CHUNK_NUM(size_t offset)
{
    return ((offset < NEXUS_CHUNK_SIZE)
                ? 0
                : 1 + ((offset - (size_t)NEXUS_CHUNK_SIZE) >> NEXUS_CHUNK_LOG));
}

static inline size_t
NEXUS_CHUNK_COUNT(size_t file_size)
{
    return NEXUS_CHUNK_NUM(file_size) + 1;
}


int
NEXUS_DISCONNECTED(void);

int nexus_mod_init(void);
int nexus_mod_exit(void);

/* prototypes called from afs */
void
nexus_kern_ping(void);

int
nexus_dentry_path(const struct dentry * dentry, char ** dest);

/**
 * Converts a vcache structure to its file path.
 * @param vcache
 * @param dest
 * @return 0 on success
 */
int
nexus_vnode_path(const struct vcache * vcache, char ** dest);

/**
 * @param parent_directory is the dentry to the parent directory
 * @param plain_name is the name of new file/directory
 * @param type if it is a file or directory
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_kern_create(struct vcache *  parent_directory,
                  char *           plain_name,
                  nexus_fs_obj_type_t type,
                  char **          dest_obfuscated_name);

/**
 * @param parent_directory
 * @param plain_name is the name of new file/directory/symlink
 * @param type file/directory/symlink
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_kern_lookup(struct vcache *  parent_directory,
                  char *           plain_name,
                  nexus_fs_obj_type_t type,
                  char **          dest_obfuscated_name);

/**
 * @param parent_dentry is the dentry to the parent directory
 * @param plain_name is the name of new file/directory
 * @param type if it is a file or directory
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_kern_remove(struct vcache *  parent_directory,
                  char *           plain_name,
                  nexus_fs_obj_type_t type,
                  char **          dest_obfuscated_name);

/**
 * @param directory, the directory which is being listed
 * @param obfuscated_name is the file/directory/symlink
 * @param type if it is a file/directory/symlink
 * @param dest_plain_name is the corresponding name from the daemon
 */
int
nexus_kern_filldir(char *           parent_directory,
                   char *           obfuscated_name,
                   nexus_fs_obj_type_t type,
                   char **          dest_plain_name);

/**
 * @param source_dir the source directory
 * @param oldname the old name
 * @param dest_dir
 * @param newname
 * @param old_obfuscated_name
 * @param new_obfuscated_name
 */
int
nexus_kern_rename(struct vcache * source_dir,
                  char *          oldname,
                  struct vcache * dest_dir,
                  char *          newname,
                  char **         old_obfuscated_name,
                  char **         new_obfuscated_name);

/**
 * @param source_link is the existing file
 * @param target_link will be the new hardlink
 * @param dest_obfuscated_name will be the new link's obfuscated name
 */
int
nexus_kern_hardlink(struct dentry * existing_link,
                    struct dentry * new_link,
                    char **         dest_obfuscated_name);

/**
 * @param dentry path to the new "symlink"
 * @param symlink_target this is the path the link will point to
 * @param dest_obfuscated_name
 */
int
nexus_kern_symlink(struct dentry * dentry,
                   char *          symlink_target,
                   char **         dest_obfuscated_name);
/**
 * @param vcache the file being saved
 * @param dirty_dcaches the list of all the dirty dcache entries
 * @param total_size amount of data to transfer (could be less than the file
 * size)
 * @param anewDV data version, must be incremented on success (AFS)
 * @param doProcessFS whether to refresh the vcache. Usually set to 1 (AFS)
 * @param nchunks the number of chunks
 * @param nomore if there are chunks left
 * @param rx_call is the pointer to the RPC context (already initialized by AFS)
 * @param filepath the path to the file
 * @param starting_offset the offset to the first chunk
 * @param store_ops functions current store operation (AFS)
 * @param store_ops_data the data related to the store operation (AFS)
 */
nexus_ret_t
nexus_kern_store(struct vcache *         vcache,
                 struct dcache **        dirty_dcaches,
                 afs_size_t              total_size,
                 afs_hyper_t *           anewDV,
                 int *                   doProcessFS,
                 struct AFSFetchStatus * OutStatus,
                 afs_uint32              nchunks,
                 int                     nomore,
                 struct rx_call *        rx_call,
                 char *                  filepath,
                 int                     starting_offset,
                 struct storeOps *       store_ops,
                 void *                  store_ops_data);
/*
 * @param afs_conn the afs connection to the server
 * @param rxconn an RPC connection with the server.
 * @param fp a pointer to the raw chunk file (chunks are saved as files on disk)
 * @param starting_offset
 * @param dcache
 * @param vcache
 * @param dcache_size the size of the dcache entry
 * @param rx_call RPC context with the server
 * @param filepath
 */
nexus_ret_t
nexus_kern_fetch(struct afs_conn *      afs_conn,
                 struct rx_connection * rxconn,
                 struct osi_file *      fp,
                 afs_size_t             starting_offset,
                 struct dcache *        dcache,
                 struct vcache *        vcache,
                 afs_int32              dcache_size,
                 struct rx_call *       rx_call,
                 char *                 filepath);

/**
 * @param vcache
 * @param acl_data AFS formatted acl data
 */
int
nexus_kern_storeacl(struct vcache * avc, AFSOpaque * acl_data);


static inline nexus_fs_obj_type_t
dentry_type(const struct dentry * dentry)
{
    if (d_is_file(dentry)) {
        return NEXUS_FILE;
    } else if (d_is_dir(dentry)) {
        return NEXUS_DIR;
    } else if (d_is_symlink(dentry)) {
        return NEXUS_LINK;
    }

    return NEXUS_ANY;
}

static inline nexus_fs_obj_type_t
vnode_type(const struct vcache * vnode)
{
    if (vnode == NULL) {
        return NEXUS_ANY;
    }

    switch (vType(vnode)) {
    case VREG:
        return NEXUS_FILE;
    case VDIR:
        return NEXUS_DIR;
    case VLNK:
        return NEXUS_LINK;
    }

    return NEXUS_ANY;
}
