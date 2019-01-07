/**
 * Defines the main data structures of our small VFS
 *
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */
#pragma once

#include <pthread.h>

#define FUSE_USE_VERSION 31

#include <fuse3/fuse_lowlevel.h>

#include <list.h> // from nexus


#define NEXUS_CHUNK_LOG2    (20)
#define NEXUS_CHUNK_SIZE    (1 << NEXUS_CHUNK_LOG2)


struct my_dentry;



struct file_chunk {
    bool             is_dirty;
    bool             is_valid;

    uint8_t *        buffer;
    size_t           size;
    size_t           base;
    size_t           index;
    struct list_head node;

    struct my_inode * inode;
};


struct my_inode {
    struct nexus_uuid      uuid;

    fuse_ino_t             ino;

    size_t                 lookup_count;

    size_t                 refcount;

    struct nexus_fs_attr   attrs;


    time_t                 last_accessed;

    bool                   is_dirty;


    size_t                 dentry_count;

    struct list_head       dentry_list;   // all the hardlinks

    pthread_mutex_t        dentry_lock;


    size_t                 filesize;

    size_t                 chunk_count;

    struct list_head       file_chunks;


    pthread_mutex_t        lock;
};

struct my_dentry {
    char                  name[NEXUS_NAME_MAX];

    size_t                name_len;

    nexus_dirent_type_t   type;

    struct nexus_fs_lookup lookup_info;

    size_t                refcount;


    struct my_inode     * inode;

    struct my_dentry    * parent;

    struct list_head      children;

    struct list_head      siblings;

    struct list_head      aliases;  // all the aliases (hardlinks)
};


struct my_file {
    int                   fid;

    int                   flags;

    size_t                offset;

    size_t                total_recv;
    size_t                total_sent;

    char                * filepath;

    struct my_dentry    * dentry;

    struct my_inode     * inode;

    bool                  is_dirty;


    struct list_head      open_files;

    pthread_rwlock_t      io_lock;
};


struct my_dir {
    size_t                file_count;

    char                * dirpath;

    size_t                readdir_offset; // the current offset of READDIR operation

    struct my_dentry    * dentry;

    struct list_head      open_dirs;
};


int
vfs_init();

void
vfs_deinit();


struct my_dentry *
vfs_get_dentry(fuse_ino_t ino, struct my_inode ** inode_ptr);

struct my_dentry *
vfs_cache_dentry(struct my_dentry  * parent,
                 char              * name,
                 struct nexus_uuid * uuid,
                 nexus_dirent_type_t type);

struct my_dentry *
_vfs_cache_dentry(struct my_dentry * parent, char * name, struct nexus_fs_lookup * lookup_info);

void
vfs_forget_dentry(struct my_dentry * parent, char * name);


struct my_inode *
vfs_get_inode(fuse_ino_t ino);



struct my_file *
vfs_file_alloc(struct my_dentry * dentry, int flags);

void
vfs_file_free(struct my_file * file_ptr);


struct my_dir *
vfs_dir_alloc(struct my_dentry * dentry);

void
vfs_dir_free(struct my_dir * dir_ptr);


void
inode_incr_lookup(struct my_inode * inode, uint64_t count);

void
inode_decr_lookup(struct my_inode * inode, uint64_t count);

bool
inode_is_file(struct my_inode * inode);

bool
inode_is_dir(struct my_inode * inode);

struct my_inode *
inode_get(struct my_inode * inode);

void
inode_put(struct my_inode * inode);

void
inode_set_dirty(struct my_inode * inode);

void
inode_set_clean(struct my_inode * inode);


//
// io.c
//

void
file_set_clean(struct my_file * file_ptr);

void
file_set_dirty(struct my_file * file_ptr);

int
file_read(struct my_file * file_ptr,
          size_t           offset,
          size_t           size,
          uint8_t        * output_buffer,
          size_t         * output_buflen);

int
file_write(struct my_file * file_ptr,
           size_t           offset,
           size_t           size,
           uint8_t        * input_buffer,
           size_t         * bytes_written);

struct my_file *
file_open(struct my_dentry * dentry, int fid, int flags);

void
file_close(struct my_file * file_ptr);

void
__free_file_chunk(struct file_chunk * chunk);


//
// dentry.c
//

struct my_dentry *
dentry_create(struct my_dentry * parent, char * name,nexus_dirent_type_t type);

void
dentry_delete_and_free(struct my_dentry * dentry);

struct my_dentry *
dentry_alloc();

struct my_dentry *
dentry_lookup(struct my_dentry * parent, const char * name);

void
dentry_instantiate(struct my_dentry * dentry, struct my_inode * inode);

void
dentry_invalidate(struct my_dentry * dentry);

void
dentry_set_name(struct my_dentry * dentry, const char * name);

char *
dentry_get_fullpath(struct my_dentry * dentry);

char *
dentry_get_parent_fullpath(struct my_dentry * dentry);


// copies the inode stat attributes into a destination buffer
void
dentry_export_attrs(struct my_dentry * dentry, struct stat * st_dest);


struct my_dentry *
dentry_get(struct my_dentry * dentry);

void
dentry_put(struct my_dentry * dentry);


void
__free_file_chunk(struct file_chunk * chunk);
